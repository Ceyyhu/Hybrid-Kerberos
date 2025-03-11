import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;
public class Main extends Application {
    private KDC kdc;
    private Client currentClient;
    private FileLogger logger;

    @Override
    public void start(Stage primaryStage) throws Exception {

        Label clientLabel = new Label("Client ID:");
        TextField clientField = new TextField();
        Label passwordLabel = new Label("Password:");
        PasswordField passwordField = new PasswordField();
        Label serverLabel = new Label("Server ID:");
        TextField serverField = new TextField();
        Label messageLabel = new Label("Message:");
        TextField messageField = new TextField();
        TextArea logArea = new TextArea();
        logArea.setEditable(false);

        Button registerButton = new Button("Register");
        Button loginButton = new Button("LogIn");
        Button communicateButton = new Button("Communicate with Server");

        VBox root = new VBox(10,
                new HBox(10, clientLabel, clientField),
                new HBox(10, passwordLabel, passwordField),
                new HBox(10, serverLabel, serverField),
                new HBox(10, messageLabel, messageField),
                new HBox(10, registerButton, loginButton, communicateButton),
                new Label("Logs:"),
                logArea
        );
        root.setPadding(new Insets(10));

        Scene scene = new Scene(root, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Kerberos Hybrid System");

        // Initialize HKS and logger
        kdc = new KDC();
        logger = new FileLogger("log.txt");

        registerButton.setOnAction(e -> {
            String clientId = clientField.getText();
            String password = passwordField.getText();
            String serverId = serverField.getText();

            try {
                currentClient = kdc.registerClient(clientId, password, serverId);
                logArea.appendText("Client registered successfully\n");
                logger.log("Client " + clientId + " registered successfully");
            } catch (Exception ex) {
                logArea.appendText("Registration failed: " + ex.getMessage() + "\n");
                logger.log("Registration failed for client " + clientId + ": " + ex.getMessage());
            }
        });

        loginButton.setOnAction(e -> {
            String clientId = clientField.getText();
            String password = passwordField.getText();
            String serverId = serverField.getText();

            try {
                logArea.appendText("Authenticating client...\n");
                boolean success = kdc.authenticateClient(clientId, password, serverId);
                //currentClient.setTicket(ticket);
                logArea.appendText("Authentication successful! Ticket granted.\n");
                logger.log("Authentication successful! Ticket granted.");
                logger.log("Client " + clientId + " logged in successfully");
            } catch (Exception ex) {
                logArea.appendText("Login failed: " + ex.getMessage() + "\n");
                logger.log("Login failed for client " + clientId + ": " + ex.getMessage());
            }
        });

        communicateButton.setOnAction(e -> {
            if (currentClient == null || currentClient.getTicket() == null) {
                logArea.appendText("Please login first\n");
                return;
            }

            String message = messageField.getText();
            if (message.isEmpty()) {
                logArea.appendText("Message cannot be empty\n");
                return;
            }

            try {
                logArea.appendText("Using ticket to communicate with the server...\n");
                String response = currentClient.communicateWithServer(messageField.getText());

                logArea.appendText("Server response: " + response + "\n");
                logger.log("Communication successful between " + currentClient.getClientId() + " and server");
            } catch (Exception ex) {
                logArea.appendText("Communication failed: " + ex.toString() + "\n");
                ex.printStackTrace();
                logger.log("Communication failed: " + ex.toString());
            }
        });

        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
