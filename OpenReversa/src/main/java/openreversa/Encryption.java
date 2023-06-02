package openreversa;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @author Robin Paquet and Arnaud Delcorte
 *
 * The Encryption class provides methods for generating salt values, hashing passwords,
 * encrypting passwords using a salt, and verifying password matches.
 */
public class Encryption {
    private static final Random random = new SecureRandom();
    private static final String characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int iterations = 10000;
    private static final int keylength = 256;

    /**
     * Generates a salt value of the specified length.
     *
     * @param length  The length of the salt value to generate.
     * @return The generated salt value as a string.
     */
    public static String getSaltvalue(int length) {
        StringBuilder finalval = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            finalval.append(characters.charAt(random.nextInt(characters.length())));
        }

        return new String(finalval);
    }

    /**
     * Hashes a password using the provided salt value.
     *
     * @param password The password to hash.
     * @param salt     The salt value used for hashing.
     * @return The hashed password as a byte array.
     * @throws AssertionError if an error occurs during hashing.
     */
    public static byte[] hash(char[] password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keylength);
        Arrays.fill(password, Character.MIN_VALUE);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new AssertionError("Error while hashing a password: " + e.getMessage(), e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Encrypts a password using the original password and salt value.
     *
     * @param password The password to encrypt.
     * @param salt     The salt value used for encryption.
     * @return The encrypted password as a string.
     */
    public static String generateSecurePassword(String password, String salt) {
        String finalval = null;

        byte[] securePassword = hash(password.toCharArray(), salt.getBytes());

        finalval = Base64.getEncoder().encodeToString(securePassword);

        return finalval;
    }

    /**
     * Verifies if a provided password matches the secured password using the salt value.
     *
     * @param providedPassword The password provided for verification.
     * @param securedPassword  The secured password to compare against.
     * @param salt             The salt value used for encryption.
     * @return true if the passwords match, false otherwise.
     */
    public static boolean verifyUserPassword(String providedPassword,
                                             String securedPassword, String salt) {
        boolean finalval = false;

        /* Generate New secure password with the same salt */
        String newSecurePassword = generateSecurePassword(providedPassword, salt);

        /* Check if two passwords are equal */
        finalval = newSecurePassword.equalsIgnoreCase(securedPassword);

        return finalval;
    }
}