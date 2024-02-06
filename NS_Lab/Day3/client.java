import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.io.*;
import java.net.*;
import java.util.Base64;

class Client {
    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";

    private SecretKey secretKey;

    public Client(String address, int port) {
        try {
            // Generate a DES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            secretKey = keyGenerator.generateKey();

            // Connect to the server
            Socket socket = new Socket(address, port);
            System.out.println("Connected to server.");

            // Initialize streams
            DataInputStream in = new DataInputStream(System.in);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Communication loop
            String messageToSend;
            while (true) {
                // Your message to be sent
                messageToSend = in.readLine();

                // Encrypt the message before sending
                String encryptedMessage = encrypt(messageToSend);
                out.writeUTF(encryptedMessage);
                System.out.println("Sent (Encrypted): " + encryptedMessage);

                // Receive the encrypted response
                String encryptedResponse = in.readUTF();

                // Decrypt the response
                String decryptedResponse = decrypt(encryptedResponse);
                System.out.println("Received (Encrypted): " + encryptedResponse);
                System.out.println("Decrypted Response: " + decryptedResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]); // Use an Initialization Vector (IV)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]); // Use the same IV as in encryption
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        new Client("127.0.0.1", 5000);
    }
}
