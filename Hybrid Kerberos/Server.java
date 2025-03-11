import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Server {
    private String serverId;
    private PrivateKey privateKey; // In real implementation, this would be securely stored
    private SecretKey sessionKey;
    private final FileLogger logger;
    private Ticket ticket;
    private KDC kdc;

    public PublicKey publicKey;

    private KeyPair keyPair;

    public Server(String serverId, KeyPair keyPair, KDC kdc) {
        this.serverId = serverId;
        this.keyPair = keyPair;
        this.privateKey = keyPair.getPrivate();
        this.logger = new FileLogger("log.txt");
        this.publicKey = keyPair.getPublic();
        this.kdc = kdc;

        // In a real implementation, the private key would be loaded securely
    }

    public String getServerId() {
        return this.serverId;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public String communicateWithClient(byte[] encryptedMessage) throws Exception {
        byte[] sessionKey = decryptSessionKey();
        SecretKeySpec aesKey = new SecretKeySpec(sessionKey, "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

        // Process message and encrypt response
        String response = "Message received: " + new String(decryptedMessage);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(response.getBytes()));
    }

    public byte[] decryptSessionKey() throws Exception {
        byte[] privateKeyBytes = kdc.getPrivateKeyForDecryption(serverId, false);
        if (privateKeyBytes == null) {
            throw new Exception("Could not retrieve private key from KDC");
        }

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ticket.getEncryptedKey());
    }


    public byte[] getMessage(byte[] encryptedMessage) {
        try {
            byte[] decryptedServerSessionKey = decryptSessionKey();
            SecretKeySpec sessionKeySpec = new SecretKeySpec(decryptedServerSessionKey, "AES");

            Cipher decryptCipher = Cipher.getInstance("AES");
            decryptCipher.init(Cipher.DECRYPT_MODE, sessionKeySpec);

            //byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedMessage = decryptCipher.doFinal(encryptedMessage);

            String decryptedMessageString = new String(decryptedMessage);
            String sendBackMessage = "Message: " + decryptedMessageString + " is recieved.";

            Cipher encryptCipher = Cipher.getInstance("AES");
            encryptCipher.init(Cipher.ENCRYPT_MODE, sessionKeySpec);

            byte[] returnedMessage = encryptCipher.doFinal(sendBackMessage.getBytes());

            return returnedMessage;
        } catch (Exception e) {

        }
        return "".getBytes();
    }

    public boolean tryToCommunicate(byte[] encryptedClientSessionKey) {
        try {
            // Server'ın kendi session key'ini decrypt et
            byte[] serverSessionKey = decryptSessionKey();
            logger.log("Server session key decrypted successfully");

            // Client'tan gelen encrypted session key'i decrypt et
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] clientSessionKey = cipher.doFinal(encryptedClientSessionKey);
            logger.log("Client session key decrypted successfully");

            // İki key'i karşılaştır
            boolean keysMatch = Arrays.equals(serverSessionKey, clientSessionKey);
            if (keysMatch) {
                logger.log("Session keys match successfully");
            } else {
                logger.log("Session keys do not match");
                logger.log("Server Key Length: " + serverSessionKey.length);
                logger.log("Client Key Length: " + clientSessionKey.length);
            }
            return keysMatch;
        } catch (Exception e) {
            logger.log("Error in tryToCommunicate: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    /* public void setSessionKey(SecretKey sessionKey) {
        this.sessionKey = sessionKey;
    }*/
}
