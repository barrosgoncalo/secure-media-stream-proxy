import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SecurityUtils {

    private static final String ALGO = "AES";
    private static final String CONFIG = "AES/GCM/NoPadding";

    public final int GCM_IV_LENGTH = 12;
    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] encrypt(String data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {


        byte[] iv = new byte[GCM_I]

        IvParameterSpec dps= new IvParameterSpec(iv);
        // Comment last line for modes that don't operate with IVs

        KeyGenerator kg = KeyGenerator.getInstance(ALGO);
        kg.init(256);

        // Initialize the cryptosuite parameterization
        Cipher c = Cipher.getInstance(CONFIG);

        Key key = kg.generateKey();

        c.init(Cipher.ENCRYPT_MODE, key, dps);
        //c.init(Cipher.ENCRYPT_MODE, key);	    


        byte plaintext[] = data.getBytes(); // input plaintext

        byte ciphertext[] = c.doFinal(plaintext);  // out ciphertext

        return ciphertext;
    }

}

