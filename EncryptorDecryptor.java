/*import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.util.Base64;

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

    // Decrypt a file using the specified key
    public static void decryptFile(File inputFile, File outputFile, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

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

    // Generate a new AES key for encryption and decryption
    public static String generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);  // AES supports 128, 192, or 256-bit keys
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // Store a key in the KeyStore
    public static void storeKeyInKeystore(String keyAlias, String key) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS"); // JCEKS is used for storing keys
        char[] password = "keystorepassword".toCharArray();
        keyStore.load(null, password);

        // Convert the string key to a SecretKey
        SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");

        // Store the key in the keystore
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(keyAlias, entry, new KeyStore.PasswordProtection(password));

        // Save the keystore to a file
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

        // Return the key as a Base64-encoded string
        return Base64.getEncoder().encodeToString(entry.getSecretKey().getEncoded());
    }

    public static void main(String[] args) {
        try {
            // Generate a secret key and store it in the keystore
            String key = generateKey();
            System.out.println("Generated Key: " + key);
            storeKeyInKeystore("mySecretKeyAlias", key);

            // Retrieve the key from the keystore
            String retrievedKey = getKeyFromKeystore("mySecretKeyAlias");
            System.out.println("Retrieved Key: " + retrievedKey);

            // Sample file encryption and decryption
            File inputFile = new File("input.txt");
            File encryptedFile = new File("encrypted_file.enc");
            File decryptedFile = new File("decrypted_file.txt");

            // Encrypt the file
            encryptFile(inputFile, encryptedFile, retrievedKey);
            System.out.println("File encrypted successfully.");

            // Decrypt the file
            decryptFile(encryptedFile, decryptedFile, retrievedKey);
            System.out.println("File decrypted successfully.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.Base64;

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

    // Decrypt a file using the specified key
    public static void decryptFile(File inputFile, File outputFile, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {

            CipherOutputStream cipherOut = new CipherOutputStream(outputStream, cipher);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
            }
            cipherOut.close();
        }
    }

    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

            // Take input data to be written to the file
            System.out.println("Enter the data to be stored in the file:");
            String data = reader.readLine();

            // Write data to the input file
            File inputFile = new File("input.txt");
            try (FileWriter writer = new FileWriter(inputFile)) {
                writer.write(data);
            }
            System.out.println("Data written to input.txt.");

            // Take the encryption key from the user
            System.out.println("Enter a 16-character encryption key (e.g., '1234567890123456'):");
            String key = reader.readLine();

            if (key.length() != 16) {
                throw new IllegalArgumentException("The key must be 16 characters long.");
            }

            // Encrypt the file
            File encryptedFile = new File("encrypted_file.enc");
            encryptFile(inputFile, encryptedFile, key);
            System.out.println("File encrypted successfully and saved as encrypted_file.enc.");

            // Decrypt the file
            File decryptedFile = new File("decrypted_file.txt");
            decryptFile(encryptedFile, decryptedFile, key);
            System.out.println("File decrypted successfully and saved as decrypted_file.txt.");

            // Display the contents of the decrypted file
            System.out.println("Decrypted file contents:");
            try (BufferedReader decryptedReader = new BufferedReader(new FileReader(decryptedFile))) {
                String line;
                while ((line = decryptedReader.readLine()) != null) {
                    System.out.println(line);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
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

    // Decrypt a file using the specified key
    public static void decryptFile(File inputFile, File outputFile, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

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

    // Generate a new AES key for encryption and decryption
    public static String generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);  // AES supports 128, 192, or 256-bit keys
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    // Store a key in the KeyStore
    public static void storeKeyInKeystore(String keyAlias, String key) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JCEKS"); // JCEKS is used for storing keys
        char[] password = "keystorepassword".toCharArray();
        keyStore.load(null, password);

        // Convert the string key to a SecretKey
        SecretKeySpec secretKey = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");

        // Store the key in the keystore
        KeyStore.SecretKeyEntry entry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry(keyAlias, entry, new KeyStore.PasswordProtection(password));

        // Save the keystore to a file
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

        // Return the key as a Base64-encoded string
        return Base64.getEncoder().encodeToString(entry.getSecretKey().getEncoded());
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {
            // Ask user for the key
            System.out.print("Enter the encryption key (16 characters): ");
            String key = scanner.nextLine();

            // Generate the secret key and store it in the keystore
            storeKeyInKeystore("mySecretKeyAlias", key);

            // Retrieve the key from the keystore
            String retrievedKey = getKeyFromKeystore("mySecretKeyAlias");

            // Sample file encryption and decryption
            File inputFile = new File("input.txt");

            // Write data to input.txt
            System.out.println("Enter the data to be stored in the file:");
            String data = scanner.nextLine();
            try (FileWriter writer = new FileWriter(inputFile)) {
                writer.write(data);
            }

            File encryptedFile = new File("encrypted_file.enc");
            File decryptedFile = new File("decrypted_file.txt");

            // Encrypt the file
            encryptFile(inputFile, encryptedFile, retrievedKey);
            System.out.println("File encrypted successfully.");

            // Ask user to provide the key for decryption
            System.out.print("Enter the encryption key for decryption: ");
            String decryptKey = scanner.nextLine();

            if (decryptKey.equals(retrievedKey)) {
                // Decrypt the file
                decryptFile(encryptedFile, decryptedFile, decryptKey);
                System.out.println("File decrypted successfully.");
                
                // Display the contents of the decrypted file
                try (BufferedReader reader = new BufferedReader(new FileReader(decryptedFile))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println("Decrypted file content: " + line);
                    }
                }
            } else {
                System.out.println("Incorrect key! Cannot decrypt the file.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}*/
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
