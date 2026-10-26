import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class FileCrypto {

    private static final byte[] MAGIC = {'C', 'F', 'E', '1'};
    private static final int SALT_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int ITERATIONS = 210_000;
    private static final int KEY_LENGTH_BITS = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    // Encrypt file bytes using a password.
    public static byte[] encrypt(byte[] input, char[] password)
            throws Exception {

        byte[] salt = new byte[SALT_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];

        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(nonce);

        SecretKeySpec key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encryptedData = cipher.doFinal(input);

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        output.write(MAGIC);
        output.write(salt);
        output.write(nonce);
        output.write(encryptedData);

        return output.toByteArray();
    }

    // Decrypt file bytes using the same password.
    public static byte[] decrypt(byte[] input, char[] password)
            throws Exception {

        int headerLength = MAGIC.length + SALT_LENGTH + NONCE_LENGTH;

        if (input == null || input.length <= headerLength) {
            throw new IllegalArgumentException("Invalid encrypted file.");
        }

        // Check the file format marker.
        for (int i = 0; i < MAGIC.length; i++) {
            if (input[i] != MAGIC[i]) {
                throw new IllegalArgumentException(
                        "This is not a Custom File Encrypter file.");
            }
        }

        byte[] salt = Arrays.copyOfRange(
                input, MAGIC.length, MAGIC.length + SALT_LENGTH);

        byte[] nonce = Arrays.copyOfRange(
                input, MAGIC.length + SALT_LENGTH, headerLength);

        byte[] encryptedData =
                Arrays.copyOfRange(input, headerLength, input.length);

        SecretKeySpec key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(TAG_LENGTH_BITS, nonce);

        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        // A wrong password or altered encrypted file will fail here.
        return cipher.doFinal(encryptedData);
    }

    // Derive a strong AES key from the password and random salt.
    private static SecretKeySpec deriveKey(char[] password, byte[] salt)
            throws Exception {

        PBEKeySpec keySpec = new PBEKeySpec(
                password, salt, ITERATIONS, KEY_LENGTH_BITS);

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();

            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            keySpec.clearPassword();
        }
    }
}