package com.gundam;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;

public class FieldEncryptor {
    // You may want to store the key securely, not in code
    private static final String KEY = "F3b7sX9qT2mZ0wVxK8r1N5j2Y4u6L0pQ"; // 32 bytes (AES-256)
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    // Encrypt a single value and return as base64
    public static String encrypt(String value) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedBytes = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt a single base64-encoded value
    public static String decrypt(String encryptedBase64) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedBase64);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    // Encrypt specified fields in a properties file
    public static void encryptFields(String filePath, Set<String> fields) throws Exception {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(filePath)) {
            props.load(in);
        }

        boolean changed = false;
        for (String key : fields) {
            String value = props.getProperty(key);
            if (value != null && !value.startsWith("{enc}")) {
                String encrypted = encrypt(value);
                props.setProperty(key, "{enc}" + encrypted);
                changed = true;
            }
        }
        if (changed) {
            try (OutputStream out = new FileOutputStream(filePath)) {
                props.store(out, "Encrypted specified fields");
            }
            System.out.println("Encryption complete.");
        } else {
            System.out.println("No values updated or already encrypted.");
        }
    }

    // Decrypt specified fields in a properties file
    public static void decryptFields(String filePath, Set<String> fields) throws Exception {
        Properties props = new Properties();
        try (InputStream in = new FileInputStream(filePath)) {
            props.load(in);
        }

        boolean changed = false;
        for (String key : fields) {
            String value = props.getProperty(key);
            if (value != null && value.startsWith("{enc}")) {
                String decrypted = decrypt(value.substring(5));
                props.setProperty(key, decrypted);
                changed = true;
            }
        }
        if (changed) {
            try (OutputStream out = new FileOutputStream(filePath)) {
                props.store(out, "Decrypted specified fields");
            }
            System.out.println("Decryption complete.");
        } else {
            System.out.println("No values updated or already decrypted.");
        }
    }

    // Usage: java FieldEncryptor -e|-d <field1,field2,...> <filename>
    public static void main(String[] args) {
        if (args.length != 3 || (!args[0].equals("-e") && !args[0].equals("-d"))) {
            System.out.println("Usage: java FieldEncryptor -e|-d <field1,field2,...> <src/main/resources/yourfile.properties>");
            System.exit(1);
        }
        String mode = args[0];
        Set<String> fields = Set.of(args[1].split(","));
        String filePath = args[2];

        try {
            if (mode.equals("-e")) {
                encryptFields(filePath, fields);
            } else {
                decryptFields(filePath, fields);
            }
        } catch (Exception ex) {
            System.out.println("Operation failed: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
}
