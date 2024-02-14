import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class EncryptorAesGcm {


    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    public static final int AES_KEY_BIT = 256;
    private static final int MAC_LENGTH_BYTE = TAG_LENGTH_BIT / 8;

    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws GeneralSecurityException {

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secret);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] cipherText = cipher.doFinal(pText);

        byte[] output = new byte[iv.length + cipherText.length + MAC_LENGTH_BYTE];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
        System.arraycopy(mac.doFinal(cipherText), 0, output, iv.length + cipherText.length, MAC_LENGTH_BYTE);
        return output;
    }

    public static byte[] decrypt(byte[] cText, SecretKey secret) throws GeneralSecurityException {

        byte[] iv = new byte[IV_LENGTH_BYTE];
        byte[] cipherText = new byte[cText.length - IV_LENGTH_BYTE - MAC_LENGTH_BYTE];
        System.arraycopy(cText, 0, iv, 0, iv.length);
        System.arraycopy(cText, iv.length, cipherText, 0, cipherText.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secret);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cipherText);

        byte[] tag = mac.doFinal(cipherText);
        byte[] providedTag = new byte[MAC_LENGTH_BYTE];
        System.arraycopy(cText, cText.length - MAC_LENGTH_BYTE, providedTag, 0, MAC_LENGTH_BYTE);
        if (!Arrays.equals(tag, providedTag)) {
            throw new GeneralSecurityException("Invalid MAC");
        }

        return plainText;
    }

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);

        // Generate a random 256-bit AES key
        SecretKey secret = CryptoUtils.getAESKey(AES_KEY_BIT);

        // Generate a random IV
        byte[] iv = CryptoUtils.getRandomNonce();

        // The data to be encrypted
        System.out.print("Enter the plaintext: ");
        String plainText = scanner.nextLine();

        // Encrypt the data
        byte[] cipherText = EncryptorAesGcm.encrypt(plainText.getBytes(StandardCharsets.UTF_8), secret, iv);

        // Print the encrypted data
        System.out.println("Encrypted data: " + Base64.getEncoder().encodeToString(cipherText));

        // Decrypt the data
        byte[] decryptedText = EncryptorAesGcm.decrypt(cipherText, secret);

        // Print the decrypted data
        System.out.println("Decrypted data: " + new String(decryptedText, StandardCharsets.UTF_8));
    }
}