import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

public class TicketGrant {
    public static void grant(Client clientInfo, Server serverInfo) throws Exception {
        String clientId = clientInfo.getClientId();
        String serverId = serverInfo.getServerId();
        Ticket clientTicket = new Ticket(clientInfo.getClientId(), serverInfo.getServerId(), LocalDateTime.now().plusMinutes(5));
        Ticket serverTicket = new Ticket(clientInfo.getClientId(), serverInfo.getServerId(), LocalDateTime.now().plusMinutes(5));

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey sessionKey = keyGen.generateKey();

        // Encrypt session key with client's and server's public keys
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE, clientInfo.publicKey);
        byte[] clientEncryptedKey = cipher.doFinal(sessionKey.getEncoded());

        cipher.init(Cipher.ENCRYPT_MODE, serverInfo.publicKey);
        byte[] serverEncryptedKey = cipher.doFinal(sessionKey.getEncoded());

        clientTicket.setEncryptedKey(clientEncryptedKey);
        serverTicket.setEncryptedKey(serverEncryptedKey);

        clientInfo.setTicket(clientTicket);
        serverInfo.setTicket(serverTicket);
    }
}
