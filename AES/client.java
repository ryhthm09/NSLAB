import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

 class AESClient {

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 12345);

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        BufferedReader serverReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

        // Read plaintext from the user
        System.out.print("Enter plaintext to send to the server: ");
        String plaintext = reader.readLine();
        System.out.println("Plaintext on client side: " + plaintext);

        
        String ciphertext = encryptAES(plaintext);
        System.out.println("CipherText on client side: " + ciphertext);
        // Send plaintext to the server
        writer.println(ciphertext);

        // Receive and print the decrypted text from the server
        String decryptedText = serverReader.readLine();
        System.out.println("Received decrypted text from server: " + decryptedText);

        // Close resources
        writer.close();
        reader.close();
        serverReader.close();
        socket.close();
    }

      private static String encryptAES(String plaintext) throws Exception {
        String keyString = "exampleKey";
        byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptAES(String ciphertext) throws Exception {
        String keyString = "exampleKey";
        byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
