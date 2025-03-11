import javax.crypto.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;

public class KDC {

    private Map<String, Client> clients;
    private Map<String, Server> servers;
    private final FileLogger logger;

    public KDC() {
        clients = new HashMap<>();
        servers = new HashMap<>();
        logger = new FileLogger("log.txt");
        loadDataset();
    }

    public Client registerClient(String clientId, String password, String serverId) throws Exception {
        if (clients.containsKey(clientId)) {
            throw new Exception("Client ID already exists");
        }

        // Generate RSA key pair for client
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair clientKeyPair = keyGen.generateKeyPair();

        // Enhanced server handling
        Server serverInfo = null;
        PrivateKey serverPrivateKey = null;
        if (serverInfo == null) {
            KeyPair serverKeyPair = keyGen.generateKeyPair();
            serverInfo = new Server(serverId, serverKeyPair,this);
            serverPrivateKey = serverKeyPair.getPrivate();
            servers.put(serverId, serverInfo);
            logger.log("Server registered: "+ serverId);
        }

        // Store client information
        Client clientInfo = new Client(clientId, password, clientKeyPair, this);
        clients.put(clientId, clientInfo);

        // Save to dataset
        saveToDataset(clientInfo, clientKeyPair.getPrivate(), serverInfo, serverPrivateKey);
        logger.log("Client registered: " + clientId);

        return clientInfo;
    }

    public boolean authenticateClient(String clientId, String password, String serverId) throws Exception {
        Client clientInfo = clients.get(clientId);
        if (clientInfo == null || !clientInfo.getPassword().equals(password)) {
            throw new Exception("Invalid credentials");
        }

        Server serverInfo = servers.get(serverId);
        if (serverInfo == null) {
            throw new Exception("Server not found");
        }

        // Create and encrypt ticket
        TicketGrant.grant( clientInfo, serverInfo);

        logger.log("Ticket issued for client " + clientId + " to server " + serverId);
        return true;
    }

    private void loadDataset() {
        try {
            File file = new File("dataset.csv");
            if (!file.exists()) {
                file.createNewFile();
                return;
            }

            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts[0].equals("CLIENT")) {
                    // CLIENT,clientId,password,publicKey,privateKey
                    String clientId = parts[1];
                    String password = parts[2];
                    byte[] publicKeyBytes = Base64.getDecoder().decode(parts[3]);
                    byte[] privateKeyBytes = Base64.getDecoder().decode(parts[4]);
                    
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
                    
                    KeyPair keyPair = new KeyPair(publicKey, privateKey);
                    clients.put(clientId, new Client(clientId, password, keyPair, this));
                }
                else if (parts[0].equals("SERVER")) {
                    // SERVER,serverId,publicKey,privateKey
                    String serverId = parts[1];
                    byte[] publicKeyBytes = Base64.getDecoder().decode(parts[2]);
                    byte[] privateKeyBytes = Base64.getDecoder().decode(parts[3]);
                    
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
                    
                    KeyPair keyPair = new KeyPair(publicKey, privateKey);
                    servers.put(serverId, new Server(serverId, keyPair, this));
                }
            }
            reader.close();
        } catch (Exception e) {
            logger.log("Error loading dataset: " + e.getMessage());
        }
    }

    private void saveToDataset(Client clientInfo, PrivateKey clientPrivateKey, Server serverInfo, PrivateKey serverPrivateKey) {
        try (PrintWriter writer = new PrintWriter(new FileWriter("dataset.csv", true))) {
            // Save client info
            String clientPrivateKeyBase64 = Base64.getEncoder().encodeToString(clientPrivateKey.getEncoded());
            String clientPublicKeyBase64 = Base64.getEncoder().encodeToString(clientInfo.publicKey.getEncoded());

            writer.println(String.format("CLIENT,%s,%s,%s,%s",
                    clientInfo.getClientId(),  // You can pass clientId here
                    clientInfo.getPassword(),  // Password can also be passed as a parameter, if needed
                    clientPublicKeyBase64,
                    clientPrivateKeyBase64
            ));

            // If server exists, save it's data
            if (serverInfo != null && serverPrivateKey != null) {
                String serverPublicKeyStr = Base64.getEncoder().encodeToString(serverInfo.publicKey.getEncoded());
                // Save Server's private key in PKCS8 format
                String serverPrivateKeyStr = Base64.getEncoder().encodeToString(serverPrivateKey.getEncoded());

                writer.println(String.format("SERVER,%s,%s,%s",
                        serverInfo.getServerId(),
                        serverPublicKeyStr,
                        serverPrivateKeyStr));
            }
            logger.log("Keys saved to dataset successfully");
        } catch (IOException e) {
            logger.log("Error saving dataset: " + e.getMessage());
        }
    }
    public Server getServer(String serverId) {
        return servers.get(serverId);
    }

    public byte[] getPrivateKeyForDecryption(String id, boolean isClient) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("dataset.csv"));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (isClient && parts[0].equals("CLIENT") && parts[1].equals(id)) {
                    reader.close();
                    return Base64.getDecoder().decode(parts[3]); // Return private key
                }
                else if (!isClient && parts[0].equals("SERVER") && parts[1].equals(id)) {
                    reader.close();
                    return Base64.getDecoder().decode(parts[2]); // Return private key
                }
            }
            reader.close();
        } catch (Exception e) {
            logger.log("Error retrieving private key: " + e.getMessage());
        }
        return null;
    }
}
