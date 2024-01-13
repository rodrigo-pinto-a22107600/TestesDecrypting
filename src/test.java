import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
public class test
{
    /* Private variable declaration */
    private static final String SECRET_KEY = "doentesspr";
    private static final String SALTVALUE = "doentessalt";

    /* Encryption Method */


    public static String encrypt(String strToEncrypt)
    {
        try
        {
            /* Declare a byte array. */
            //Este array de bytes é igual ao do fernn
            byte[] iv = {(byte) 81, (byte) 204, (byte) 206,(byte) 17, (byte) 207,(byte) 0,(byte) 49,(byte) 89, (byte) 134,(byte) 61, (byte) 189, (byte) 134, (byte) 128,(byte) 112, (byte) 250, (byte) 248};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            /* Create factory for secret keys. */
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            /* PBEKeySpec class implements KeySpec interface. */
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), 1000, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            /* Retruns encrypted value. */
//            System.out.println(Arrays.toString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8))));;
//            byte[] decodedBytes = Base64.getDecoder().decode(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
//            return new String(decodedBytes);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        }
        catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e)
        {
            System.out.println("Error occured during encryption: " + e.toString());
        }
        return null;
    }

    /* Decryption Method */
    public static String decrypt(String strToDecrypt)
    {
        try
        {
            int dkLen = 256;
            int rounds = 1000;
            PBEKeySpec keySpec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALTVALUE.getBytes(), rounds, dkLen);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] out = factory.generateSecret(keySpec).getEncoded();
            System.out.println(Arrays.toString(out));
        }
        catch (Exception e)
        {
            System.out.println("Error occured during decryption: " + e.toString());
        }
        return null;
    }
    /* Driver Code */
    public static void main(String[] args)
    {
        /* Message to be encrypted. */
        String originalval = "Rosa";
        /* Call the encrypt() method and store result of encryption. */
        String encryptedval = encrypt(originalval);
        /* Call the decrypt() method and store result of decryption. */
        String decryptedval = decrypt(encryptedval);
        /* Display the original message, encrypted message and decrypted message on the console. */
        System.out.println("Original value: " + originalval);
        System.out.println("Encrypted value: " + encryptedval);
        System.out.println("Decrypted value: " + decryptedval);
    }
}