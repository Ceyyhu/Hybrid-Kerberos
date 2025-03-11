import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class FileLogger {
    private String logFile;
    private DateTimeFormatter formatter;

    public FileLogger(String logFile) {
        this.logFile = logFile;
        this.formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    }

    public void log(String message) {
        try (FileWriter fw = new FileWriter(logFile, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            String timestamp = LocalDateTime.now().format(formatter);
            bw.write(timestamp + " - " + message + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
} 