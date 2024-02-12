import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

 class DESClient {

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 12345);

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        BufferedReader serverReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

        // Read plaintext from the user
        System.out.print("Enter plaintext to send to the server: ");
        String plaintext = reader.readLine();
        System.out.println("Plaintext on client side: " + plaintext);

        String ciphertext = encryptDES(plaintext);
        System.out.println("CipherText on client side: " + ciphertext);
        // Send plaintext to the server
        writer.println(ciphertext);

        // Receive and print the encrypted text from the server
        String decryptedText = serverReader.readLine();
        System.out.println("Received encrypted text from server: " + decryptedText);

        // Close resources
        writer.close();
        reader.close();
        serverReader.close();
        socket.close();
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
