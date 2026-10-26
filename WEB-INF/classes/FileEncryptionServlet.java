import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

@MultipartConfig(
        maxFileSize = 10 * 1024 * 1024,
        maxRequestSize = 11 * 1024 * 1024
)
public class FileEncryptionServlet extends HttpServlet {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/file_encrypter?useSSL=false&serverTimezone=UTC";
    private static final String DB_USER = "root";

    private void saveLog(String fileName, String operation) throws SQLException {
        // Read the password from Tomcat's environment, with a fallback option if needed
        String dbPassword = System.getenv("Hashir@1206");

        if (dbPassword == null || dbPassword.isEmpty()) {
            throw new SQLException("DB_PASSWORD environment variable is not set.");
        }

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL JDBC Driver not found in classpath.", e);
        }

        String sql = "INSERT INTO operation_logs (file_name, operation, status) VALUES (?, ?, ?)";

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, dbPassword);
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, fileName);
            statement.setString(2, operation);
            statement.setString(3, "SUCCESS");

            statement.executeUpdate();
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        Part filePart = request.getPart("file");
        String password = request.getParameter("password");
        String operation = request.getParameter("operation");

        if (filePart == null || password == null || password.isEmpty() || operation == null) {
            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Choose a file, enter a password, and select an operation."
            );
            return;
        }

        if (!operation.equals("encrypt") && !operation.equals("decrypt")) {
            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid operation."
            );
            return;
        }

        byte[] inputBytes;

        try (InputStream input = filePart.getInputStream()) {
            inputBytes = input.readAllBytes();
        }

        byte[] resultBytes;

        try {
            char[] passwordChars = password.toCharArray();

            if (operation.equals("encrypt")) {
                resultBytes = FileCrypto.encrypt(inputBytes, passwordChars);
            } else {
                resultBytes = FileCrypto.decrypt(inputBytes, passwordChars);
            }
        } catch (Exception e) {
            response.sendError(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "Could not process the file. Check the password and file."
            );
            return;
        }

        String originalName = filePart.getSubmittedFileName();

        if (originalName == null || originalName.isBlank()) {
            originalName = "download";
        }

        originalName = originalName.replace("\\", "/");
        originalName = originalName.substring(originalName.lastIndexOf('/') + 1);
        // Inside your doPost method, after your file processing/encryption logic succeeds:

System.out.println("=== DEBUG: About to call saveLog ===");
saveLog(originalName, operation);
System.out.println("=== DEBUG: saveLog finished successfully ===");

        // Record successful processing in MySQL.
       // Record successful processing in MySQL.
        try {
            saveLog(originalName, operation);
        } catch (Exception e) {
            System.err.println("=== DATABASE ERROR DETAILS ===");
            e.printStackTrace(); // This will print the exact reason to your console
            getServletContext().log("Database logging failed: " + e.getMessage());
            response.setHeader("X-DB-Log-Error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        String downloadName;

        if (operation.equals("encrypt")) {
            downloadName = originalName + ".enc";
        } else if (originalName.endsWith(".enc")) {
            downloadName = originalName.substring(0, originalName.length() - 4) + ".decrypted";
        } else {
            downloadName = originalName + ".decrypted";
        }

        response.setContentType("application/octet-stream");
        response.setHeader(
                "Content-Disposition",
                "attachment; filename=\"" + downloadName + "\""
        );
        response.setContentLength(resultBytes.length);

        try (OutputStream output = response.getOutputStream()) {
            output.write(resultBytes);
        }
    }
}