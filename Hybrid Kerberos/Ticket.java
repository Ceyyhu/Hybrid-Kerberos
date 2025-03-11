import javax.crypto.SecretKey;
import java.time.LocalDateTime;

public class Ticket {
    private String clientId;
    private String serverId;
    private LocalDateTime expirationTime;
    private byte[] encryptedKey;

    public Ticket(String clientId, String serverId, LocalDateTime expirationTime) {
        this.clientId = clientId;
        this.serverId = serverId;
        this.expirationTime = expirationTime;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expirationTime);
    }

    // Getters
    public String getClientId() { return clientId; }
    public String getServerId() { return serverId; }
    public byte[] getEncryptedKey() { return encryptedKey; }
    public void setEncryptedKey(byte[] encryptedKey){ this.encryptedKey = encryptedKey;}
    public LocalDateTime getExpirationTime() { return expirationTime; }
} 