package openreversa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @author Robin Paquet and Arnaud Delcorte
 * 
 * The Encryption class provides methods for secure password encryption and verification using PBKDF2.
 * PBKDF2 (Password-Based Key Derivation Function 2) is a key derivation function used to derive a cryptographic key from a password.
 * This class uses PBKDF2 with HMAC-SHA512 as the pseudo-random function and a randomly generated salt for each password.
 * It provides methods to generate a secure password and verify a user's password against a secured password.
 */
public class Encryption {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int SALT_LENGTH = 16;
    private static final int ITERATIONS = 100000;
    private static final int KEY_LENGTH = 256;

    /**
     * Generates a random salt value.
     *
     * @return The generated salt as a byte array.
     */
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes the given password with the provided salt using PBKDF2 with HMAC-SHA512.
     *
     * @param password The password to be hashed.
     * @param salt     The salt value used in the hashing process.
     * @return The hashed password as a byte array.
     * @throws AssertionError If an error occurs while hashing the password.
     */
    private static byte[] hashPassword(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        }
    }

    /**
     * Generates a secure password by hashing the provided password with a randomly generated salt.
     *
     * @param password The password to be hashed.
     * @return The generated secure password as a string in the format "salt:hashedPassword".
     * @throws NullPointerException If the password is null.
     */
    public static String generateSecurePassword(String password) {
        Objects.requireNonNull(password);
        byte[] salt = generateSalt();
        byte[] hashedPassword = hashPassword(password.toCharArray(), salt);
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hashedPassword);
    }

    /**
     * Verifies the provided password against a secured password.
     *
     * @param providedPassword The password provided by the user.
     * @param securedPassword  The secured password to be verified.
     * @return true if the provided password matches the secured password, false otherwise.
     * @throws NullPointerException     If either the providedPassword or securedPassword is null.
     * @throws IllegalArgumentException If the secured password format is invalid.
     */
    public static boolean verifyUserPassword(String providedPassword, String securedPassword) {
        Objects.requireNonNull(providedPassword);
        Objects.requireNonNull(securedPassword);
        String[] parts = securedPassword.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid secured password format");
        }
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] hashedPassword = Base64.getDecoder().decode(parts[1]);
        byte[] providedHashedPassword = hashPassword(providedPassword.toCharArray(), salt);
        return MessageDigest.isEqual(hashedPassword, providedHashedPassword);
    }
}