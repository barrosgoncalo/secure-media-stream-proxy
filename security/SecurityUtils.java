package security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.crypto.*;
import javax.crypto.spec.*;

public class SecurityUtils {

    private static final String CONFIG = "AES/GCM/NoPadding";
    private static final String ALIAS = "streamkey";
    private static final String KEYSTORE_FILE = "shared.p12";

    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static Key loadSharedKey()
        throws KeyStoreException, NoSuchAlgorithmException,
                CertificateException, FileNotFoundException,
                IOException, UnrecoverableKeyException
    {
        KeyStore ks = KeyStore.getInstance("pkcs12");
        char[] password = "changeit".toCharArray();
        try(FileInputStream in = new FileInputStream(KEYSTORE_FILE)) {
            ks.load(in, password);
        }

        return ks.getKey(ALIAS, password);
    }

    public static byte[] encrypt(byte[] plaintext, Key key, byte[] iv) 
        throws NoSuchAlgorithmException, NoSuchPaddingException,
                InvalidKeyException, InvalidAlgorithmParameterException,
                IllegalBlockSizeException, BadPaddingException
    {
        GCMParameterSpec dps = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            
        Cipher c = Cipher.getInstance(CONFIG);
        c.init(Cipher.ENCRYPT_MODE, key, dps);

        return c.doFinal( plaintext );
    }

    public static byte[] decrypt(byte[] ciphertext, Key key, byte[] iv)
        throws IllegalBlockSizeException, BadPaddingException,
                InvalidKeyException, NoSuchAlgorithmException,
                NoSuchPaddingException, InvalidAlgorithmParameterException
    {
        GCMParameterSpec dps = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        Cipher c = Cipher.getInstance(CONFIG);
        c.init(Cipher.DECRYPT_MODE, key, dps);

        return c.doFinal( ciphertext );
    }


}
