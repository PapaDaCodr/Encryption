import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class EncryptorAesGcmTest {

    public static void main(String[] args) throws Exception {

        // Generate a random 256-bit AES key
        SecretKey secret = CryptoUtils.getAESKey(EncryptorAesGcm.AES_KEY_BIT);

        // Generate a random IV
        byte[] iv = CryptoUtils.getRandomNonce();

        // The data to be encrypted
        String plainText = "Hello, World!";

        // Encrypt the data
        byte[] cipherText = EncryptorAesGcm.encrypt(plainText.getBytes(StandardCharsets.UTF_8), secret, iv);

        // Print the encrypted data
        System.out.println("Encrypted  " + CryptoUtils.base64(cipherText));

        // Decrypt the data
        byte[] decryptedText = EncryptorAesGcm.decrypt(cipherText, secret);

        // Print the decrypted data
        System.out.println("Decrypted data: " + new String(decryptedText, StandardCharsets.UTF_8));
    }

}