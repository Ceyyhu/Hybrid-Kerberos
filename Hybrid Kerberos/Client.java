import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private String clientId;
    private String password;
    private KeyPair keyPair;
    private Ticket ticket;
    private KDC kdc;
    public PublicKey publicKey;
    private final FileLogger logger;

    public Client(String clientId, String password, KeyPair keyPair, KDC kdc) {
        this.clientId = clientId;
        this.password = password;
        this.keyPair = keyPair;
        this.kdc = kdc;
        this.publicKey = keyPair.getPublic();
        this.logger = new FileLogger("log.txt");
    }

    public String getClientId() { return this.clientId; }
    public Ticket getTicket() { return this.ticket; }
    public String getPassword(){ return this.password; }
    public void setTicket(Ticket ticket) { this.ticket = ticket; }

    public String communicateWithServer(String message) throws Exception {
        if (ticket == null) {
            throw new Exception("No valid ticket");
        }

        Server server = kdc.getServer(ticket.getServerId());
        if (server == null) {
            throw new Exception("Server not found");
        }

        try {
            // Client session key'i decrypt et
            logger.log("Decrypting client session key...");
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] sessionKey = cipher.doFinal(ticket.getEncryptedKey());
            logger.log("Client session key decrypted successfully");

            // Session key'i server'ın public key'i ile encrypt et
            logger.log("Encrypting session key for server verification...");
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, server.publicKey);
            byte[] encryptedSessionKey = cipher.doFinal(sessionKey);
            logger.log("Session key encrypted for server");

            // Server ile session key doğrulaması yap
            logger.log("Attempting to verify session key with server...");
            boolean canCommunicate = server.tryToCommunicate(encryptedSessionKey);
            if (!canCommunicate) {
                throw new Exception("Session key verification failed");
            }
            logger.log("Session key verified successfully");

            // Mesajı AES ile encrypt et
            SecretKeySpec aesKey = new SecretKeySpec(sessionKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());

            // Server'dan cevap al
            byte[] response = server.getMessage(encryptedMessage);

            // Cevabı decrypt et
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedResponse = aesCipher.doFinal(response);
            return new String(decryptedResponse);

        } catch (Exception e) {
            logger.log("Communication error: " + e.getMessage());
            throw new Exception("Communication error: " + e.getMessage());
        }
    }
} 