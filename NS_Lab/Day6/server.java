import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class AESServer {

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server waiting for connection...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket);

            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

            // Read plaintext from the client
            String plaintext = reader.readLine();
            System.out.println("Received plaintext from client: " + plaintext);

            String keyString = "exampleKey"; // Replace with your actual key
            String ciphertext = encryptAES(plaintext);
            System.out.println("Encrypted text: " + ciphertext);
            String decryptedText = decryptAES(ciphertext);

            // Send the decrypted text back to the client
            writer.println(decryptedText);

            // Decrypt the ciphertext on the server side
            System.out.println("Decrypted text on server side: " + decryptedText);

            // Close resources
            writer.close();
            reader.close();
            clientSocket.close();
        }
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
