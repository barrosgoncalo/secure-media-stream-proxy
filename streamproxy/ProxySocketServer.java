package streamproxy;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import security.SecurityUtils;

import static security.SecurityUtils.GCM_IV_LENGTH;
import static security.SecurityUtils.GCM_TAG_LENGTH_BITS;

/**
 * Proxy implemented with raw sockets only (java.net.ServerSocket / Socket), no
 * com.sun.net.httpserver, no java.net.http.HttpClient, no external libraries.
 * Serves a small page at "/" and relays GET /video/<file> to the origin server,
 * forwarding the Range header and streaming the response body back block by
 * block (no whole-file buffering). Each browser connection handles one request,
 * then closes.
 *
 * Usage: java ProxySocketServer [port=8080] [originHost=localhost] [originPort=8081]
 */
public class ProxySocketServer {

    static final int BLOCK_SIZE = 1024;
    static final int FRAME_SIZE = BLOCK_SIZE + GCM_IV_LENGTH + GCM_TAG_LENGTH_BITS;

    static final String INDEX_HTML = """
            <!doctype html>
            <html><head><meta charset="utf-8"><title>MP4 via socket-only proxy</title></head>
            <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
              <h1>MP4 streamed through a plain-socket proxy</h1>
              <p>File: <input id="f" value="sample.mp4">
                 <button onclick="load()">Load</button></p>
              <video id="v" controls preload="metadata" style="width:100%"></video>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
                  v.load();
                }
                load();
              </script>
            </body></html>
            """;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        String originHost = args.length > 1 ? args[1] : "localhost";
        int originPort = args.length > 2 ? Integer.parseInt(args[2]) : 8081;

        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("Proxy on http://localhost:" + port + "/  ->  http://" + originHost + ":" + originPort);
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, originHost, originPort));
            }
        }
    }

    static void handle(Socket browser, String originHost, int originPort) {
        try (browser) {
            InputStream in = browser.getInputStream();
            OutputStream out = browser.getOutputStream();

            String requestLine = HttpUtil.readLine(in);
            if (requestLine == null || !requestLine.startsWith("GET ")) {
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }
            String path = requestLine.split(" ")[1];

            String rangeHeader = null;
            String line;
            while ((line = HttpUtil.readLine(in)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c > 0 && line.substring(0, c).equalsIgnoreCase("Range")) {
                    rangeHeader = line.substring(c + 1).trim();
                }
            }

            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }
            if (!path.startsWith("/video/")) {
                writeSimpleStatus(out, 404, "Not Found");
                return;
            }

            String name = path.substring("/video/".length());
            relayFromOrigin(out, originHost, originPort, name, rangeHeader);

        } catch (IOException e) {
            // Browser disconnected or origin unreachable mid-stream: nothing to do.
        }
    }

    static void servePage(OutputStream out) throws IOException {
        byte[] page = INDEX_HTML.getBytes(StandardCharsets.UTF_8);
        StringBuilder headers = new StringBuilder();
        headers.append("HTTP/1.1 200 OK\r\n")
                .append("Content-Type: text/html; charset=utf-8\r\n")
                .append("Content-Length: ").append(page.length).append("\r\n")
                .append("Connection: close\r\n\r\n");
        out.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(page);
        out.flush();
    }

    static void relayFromOrigin(OutputStream browserOut, String originHost, int originPort,
                                 String name, String rangeHeader) throws IOException, InvalidKeyException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException {
        try (Socket origin = new Socket(originHost, originPort)) {
            OutputStream originOut = origin.getOutputStream();
            InputStream originIn = origin.getInputStream();

            StringBuilder req = new StringBuilder();
            req.append("GET /media/").append(name).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(originHost).append(":").append(originPort).append("\r\n");
            if (rangeHeader != null) req.append("Range: ").append(rangeHeader).append("\r\n");
            req.append("Connection: close\r\n\r\n");
            originOut.write(req.toString().getBytes(StandardCharsets.US_ASCII));
            originOut.flush();

            // Parse the origin's status line + headers
            String statusLine = HttpUtil.readLine(originIn);
            if (statusLine == null) {
                writeSimpleStatus(browserOut, 502, "Bad Gateway");
                return;
            }
            String[] parts = statusLine.split(" ", 3);
            int code = Integer.parseInt(parts[1]);
            String reason = parts.length > 2 ? parts[2] : "";

            long encryptedContentLength = -1;
            String contentType = null, contentRange = null, acceptRanges = null;
            String line;
            while ((line = HttpUtil.readLine(originIn)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c <= 0) continue;
                String h = line.substring(0, c).trim();
                String v = line.substring(c + 1).trim();
                switch (h.toLowerCase()) {
                    case "content-length" -> encryptedContentLength = Long.parseLong(v);
                    case "content-type" -> contentType = v;
                    case "content-range" -> contentRange = v;
                    case "accept-ranges" -> acceptRanges = v;
                }
            }

            long numChunks = ( encryptedContentLength + FRAME_SIZE - 1 ) / FRAME_SIZE;
            long plaintextContentLength = encryptedContentLength - (numChunks * 28);

            // Forward status + the headers the browser needs for playback/seeking
            StringBuilder resp = new StringBuilder();
            resp.append("HTTP/1.1 ").append(code).append(' ').append(reason).append("\r\n");
            if (contentType != null) resp.append("Content-Type: ").append(contentType).append("\r\n");
            if (acceptRanges != null) resp.append("Accept-Ranges: ").append(acceptRanges).append("\r\n");
            if (contentRange != null) resp.append("Content-Range: ").append(contentRange).append("\r\n");
            if (plaintextContentLength >= 0) resp.append("Content-Length: ").append(plaintextContentLength).append("\r\n");
            resp.append("Connection: close\r\n\r\n");
            browserOut.write(resp.toString().getBytes(StandardCharsets.US_ASCII));
            browserOut.flush();

            if (plaintextContentLength <= 0) return;

            DataInputStream dataIn = new DataInputStream(originIn);
            long remainingEncryptedBytes = encryptedContentLength;
            Key sharedKey = SecurityUtils.loadSharedKey();

            // Relay the body block by block; closing either socket cancels the transfer.
            byte[] buf = new byte[FRAME_SIZE];
            while (remainingEncryptedBytes > 0) {

                byte[] iv = new byte[SecurityUtils.GCM_IV_LENGTH];

                int n = dataIn.read(iv, 0, SecurityUtils.GCM_IV_LENGTH);
                n += dataIn.read(buf, n - 1, (int) Math.min(buf.length, remainingEncryptedBytes));

                byte[] plaintext = SecurityUtils.decrypt(buf, sharedKey, iv);
                if (n < 0) break;
                browserOut.write(plaintext);
                browserOut.flush();
                remainingEncryptedBytes -= n;
            }
        }
    }

    static void writeSimpleStatus(OutputStream out, int code, String reason) throws IOException {
        String resp = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }
}
