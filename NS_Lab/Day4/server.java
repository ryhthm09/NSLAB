import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class DESServer {

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

            // Encrypt plaintext using DES
           // String ciphertext = encryptDES(plaintext);
            System.out.println("Encrypted text: " + plaintext);
            String decryptedText = decryptDES(plaintext);

            // Send the encrypted text back to the client
            writer.println(decryptedText);

            // Decrypt the ciphertext on the server side
            //String decryptedText = decryptDES(ciphertext);
            System.out.println("Decrypted text on server side: " + decryptedText);

            // Close resources
            writer.close();
            reader.close();
            clientSocket.close();
        }
    }

    private static String encryptDES(String plaintext) throws Exception {
        String keyString = "exampleKey"; // Replace with your actual key
        DESKeySpec desKeySpec = new DESKeySpec(keyString.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptDES(String ciphertext) throws Exception {
        String keyString = "exampleKey"; // Replace with your actual key
        DESKeySpec desKeySpec = new DESKeySpec(keyString.getBytes(StandardCharsets.UTF_8));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);

        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
