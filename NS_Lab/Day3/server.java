import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.io.*;
import java.net.*;
import java.util.Base64;

 class Server {
    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";

    private SecretKey secretKey;

    public Server(int port) {
        try {
            // Generate a DES key
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            secretKey = keyGenerator.generateKey();

            // Start the server
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server started. Waiting for a client...");

            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");

            // Initialize streams
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Communication loop
            String receivedMessage;
            while (true) {
                receivedMessage = in.readUTF();

                // Decrypt the received message
                String decryptedMessage = decrypt(receivedMessage);
                System.out.println("Received (Encrypted): " + receivedMessage);
                System.out.println("Decrypted Message: " + decryptedMessage);

                // Process the message (you can replace this with your logic)

                // Send a response back (encrypt before sending)
                String response = "Server response";
                String encryptedResponse = encrypt(response);
                out.writeUTF(encryptedResponse);
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
        new Server(5000);
    }
}
