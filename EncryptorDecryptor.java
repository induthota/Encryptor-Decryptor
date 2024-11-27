import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Scanner;

public class EncryptorDecryptor {

    // Encrypts the input string using the specified key
    public static String encrypt(String input, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypts the input string using the specified key
    public static String decrypt(String encryptedInput, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedInput);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // Encrypt a file using the specified key
    public static void encryptFile(File inputFile, File outputFile, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile);
             CipherOutputStream cipherOut = new CipherOutputStream(outputStream, cipher)) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
            }
        }
    }

    // Decrypt and display file contents with a security check
    public static void decryptAndDisplayFile(File inputFile, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             CipherInputStream cipherInput = new CipherInputStream(inputStream, cipher);
             BufferedReader reader = new BufferedReader(new InputStreamReader(cipherInput))) {

            System.out.println("Decrypted File Contents:");
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
    }

    // Generate a new AES key for encryption and decryption
    public static String generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);  // AES supports 128, 192, or 256-bit keys
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // Store a key in the KeyStore
    public static void storeKeyInKeystore(String keyAlias, String key) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        char[] password = "keystorepassword".toCharArray();
        keyStore.load(null, password);

        SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(keyAlias, entry, new KeyStore.PasswordProtection(password));

        try (FileOutputStream keyStoreFile = new FileOutputStream("keystore.jceks")) {
            keyStore.store(keyStoreFile, password);
        }
    }

    // Retrieve a key from the KeyStore
    public static String getKeyFromKeystore(String keyAlias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        char[] password = "keystorepassword".toCharArray();
        keyStore.load(new FileInputStream("keystore.jceks"), password);

        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(password);
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, protectionParam);

        return Base64.getEncoder().encodeToString(entry.getSecretKey().getEncoded());
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            // Ask user for the key
            System.out.print("Enter a 16-character encryption key: ");
            String key = scanner.nextLine();
            if (key.length() != 16) {
                System.out.println("Error: Key must be 16 characters long.");
                return;
            }

            // Store the key in the keystore
            storeKeyInKeystore("mySecretKeyAlias", key);

            // Retrieve the key from the keystore
            String retrievedKey = getKeyFromKeystore("mySecretKeyAlias");

            // File operations
            File inputFile = new File("input.txt");
            File encryptedFile = new File("encrypted_file.enc");

            // Write data to input.txt
            System.out.println("Enter the data to be stored in the file:");
            String data = scanner.nextLine();
            try (FileWriter writer = new FileWriter(inputFile)) {
                writer.write(data);
            }

            // Encrypt the file
            encryptFile(inputFile, encryptedFile, retrievedKey);
            System.out.println("File encrypted successfully.");

            // Delete the plaintext file for security
            inputFile.delete();

            // Decrypt the file and display contents
            System.out.print("Enter the encryption key to access the file: ");
            String userKey = scanner.nextLine();
            if (userKey.equals(retrievedKey)) {
                decryptAndDisplayFile(encryptedFile, userKey);
            } else {
                System.out.println("Incorrect key! Access denied.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
