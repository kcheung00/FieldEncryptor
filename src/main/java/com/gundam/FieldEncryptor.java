package com.fieldencryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SafeFieldEncryptor
 *
 * - AEAD: AES-256-GCM
 * - KDF: PBKDF2WithHmacSHA512 with high iteration count and random salt
 * - Randomness: SecureRandom for salt and IV
 * - Envelope: JSON-like string containing version, kdf, iterations, salt, iv, key_id, ciphertext
 *
 * Usage notes:
 * - Prefer using a KMS to store/encrypt keys. If using passwords, treat them as sensitive and do not keep in memory longer than needed.
 * - This implementation is intentionally dependency-free (no external JSON libs). The envelope format is simple and human-readable,
 *   but you should consider using a formal serializer (Jackson/Gson) in your project.
 */
public final class FieldEncryptor {
    private FieldEncryptor() {}

    // Format and constants
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_LENGTH_BITS = 128; // recommended
    private static final int IV_LENGTH_BYTES = 12; // recommended for GCM
    private static final int SALT_LENGTH_BYTES = 16;
    private static final int PBKDF2_ITERATIONS = 200_000; // tune based on target platform; >=200k recommended for servers
    private static final SecureRandom RNG = new SecureRandom();

    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    /**
     * Encrypt plaintext using a password-derived key.
     *
     * The returned string is a JSON-like envelope. Example:
     * {"version":1,"kdf":"PBKDF2WithHmacSHA512","iterations":200000,"salt":"...","key_id":"my-key","iv":"...","ciphertext":"..."}
     *
     * keyId can be a KMS identifier or application key label. If you use a KMS master key, prefer deriving a data key from KMS and call
     * an overload that accepts byte[] symmetricKey instead of a password.
     *
     * @param plaintext text to encrypt
     * @param password  password (as char[]) to derive a key; the method will not modify the char[] but callers should clear it when done
     * @param keyId     optional key identifier (can be null)
     * @return envelope string (safe to persist)
     * @throws Exception on crypto errors
     */
    public static String encrypt(String plaintext, char[] password, String keyId) throws Exception {
        // 1. Generate salt
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        RNG.nextBytes(salt);

        // 2. Derive key using PBKDF2
        SecretKeySpec aesKey = deriveAesKey(password, salt, PBKDF2_ITERATIONS);

        // 3. Generate IV/nonce for GCM
        byte[] iv = new byte[IV_LENGTH_BYTES];
        RNG.nextBytes(iv);

        // 4. Perform AES-GCM encryption
        Cipher cipher = Cipher.getInstance(CIPHER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // 5. Build envelope
        String envelope = String.format(
                "{\"version\":1,\"kdf\":\"%s\",\"iterations\":%d,\"salt\":\"%s\",\"key_id\":\"%s\",\"iv\":\"%s\",\"ciphertext\":\"%s\"}",
                KDF_ALGORITHM,
                PBKDF2_ITERATIONS,
                B64.encodeToString(salt),
                keyId == null ? "" : escapeJson(keyId),
                B64.encodeToString(iv),
                B64.encodeToString(ciphertext)
        );

        return envelope;
    }

    /**
     * Decrypt the envelope produced by encrypt().
     *
     * @param envelope JSON-like string returned by encrypt(...)
     * @param password password used to derive the key (char[]). Callers should zero it after use.
     * @return plaintext
     * @throws Exception on crypto errors or authentication failure
     */
    public static String decrypt(String envelope, char[] password) throws Exception {
        // Simple extraction using regex - this avoids a JSON dependency for this example.
        // Replace with a real JSON parser in production code for robustness.
        String saltB64 = extractField(envelope, "\"salt\"");
        String iterationsText = extractFieldRawNumber(envelope, "\"iterations\"");
        String ivB64 = extractField(envelope, "\"iv\"");
        String ctB64 = extractField(envelope, "\"ciphertext\"");

        if (saltB64 == null || ivB64 == null || ctB64 == null || iterationsText == null) {
            throw new IllegalArgumentException("Invalid envelope format");
        }

        int iterations = Integer.parseInt(iterationsText);

        byte[] salt = B64D.decode(saltB64);
        byte[] iv = B64D.decode(ivB64);
        byte[] ciphertext = B64D.decode(ctB64);

        SecretKeySpec aesKey = deriveAesKey(password, salt, iterations);

        Cipher cipher = Cipher.getInstance(CIPHER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    // Derives AES key bytes (256-bit) from password and salt using PBKDF2WithHmacSHA512
    private static SecretKeySpec deriveAesKey(char[] password, byte[] salt, int iterations) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, AES_KEY_BITS);
        SecretKeyFactory f = SecretKeyFactory.getInstance(KDF_ALGORITHM);
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Minimal JSON field extractor for base64 values and simple strings. Not a substitute for a proper JSON lib.
    private static String extractField(String src, String fieldName) {
        Pattern p = Pattern.compile(fieldName + "\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(src);
        if (!m.find()) return null;
        return m.group(1);
    }

    // Extract numeric field (no quotes)
    private static String extractFieldRawNumber(String src, String fieldName) {
        Pattern p = Pattern.compile(fieldName + "\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(src);
        if (!m.find()) return null;
        return m.group(1);
    }

    // Very small JSON string escaper for key_id usage; again prefer JSON library in production
    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
