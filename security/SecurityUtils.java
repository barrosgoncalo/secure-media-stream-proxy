import java.util.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.crypto.*;
import javax.crypto.spec.*;

public class SecurityUtils {

    private static final String ALGO = "AES";
    private static final String CONFIG = "AES/GCM/NoPadding";

    public static final int GCM_IV_LENGTH = 12;
    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static Key generateKey() throws NoSuchAlgorithmException {

        KeyGenerator kg = KeyGenerator.getInstance(ALGO);
        kg.init(256);

        return kg.generateKey();
    }

    public static Key loadSharedKey()
        throws KeyStoreException, NoSuchAlgorithmException,
                CertificateException, FileNotFoundException,
                IOException, UnrecoverableKeyException
    {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        char[] password = "changeit".toCharArray();
        try(FileInputStream in = new FileInputStream("shared.p12")) {
            ks.load(in, password);
        }

        return ks.getKey("streamkey", password);
    }

    public static byte[] encrypt(byte[] plaintext, Key key, byte[] iv) 
        throws NoSuchAlgorithmException, NoSuchPaddingException,
                InvalidKeyException, InvalidAlgorithmParameterException,
                IllegalBlockSizeException, BadPaddingException
    {
        IvParameterSpec dps = new IvParameterSpec(iv);
            
        Cipher c = Cipher.getInstance(CONFIG);
        c.init(Cipher.ENCRYPT_MODE, key, dps);

        return c.doFinal( plaintext );
    }

    public static byte[] decrypt(byte[] ciphertext, Key key)
        throws IllegalBlockSizeException, BadPaddingException,
                InvalidKeyException, NoSuchAlgorithmException,
                NoSuchPaddingException
    {
        Cipher c = Cipher.getInstance(CONFIG);
        c.init(Cipher.DECRYPT_MODE, key);

        return c.doFinal( ciphertext );
    }


}
