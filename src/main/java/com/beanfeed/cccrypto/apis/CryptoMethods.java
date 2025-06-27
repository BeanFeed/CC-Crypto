package com.beanfeed.cccrypto.apis;

import dan200.computercraft.api.lua.LuaException;
import dan200.computercraft.api.lua.LuaFunction;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoMethods {

    @LuaFunction
    public final String rsaEncrypt(String data, String publicKey) throws LuaException {
        // Implement RSA encryption logic here
        // This is a placeholder implementation

        try {
            return encrypt(data, publicKey);
        } catch (Exception e) {
            throw new LuaException("Failed to encrypt: " + e.getMessage());
        }
    }

    @LuaFunction
    public final String rsaDecrypt(String value, String privateKey) throws LuaException {
        // Implement RSA decryption logic here
        // This is a placeholder implementation

        try {
            return decrypt(value, privateKey);
        } catch (Exception e) {
            throw new LuaException("Failed to decrypt: " + e.getMessage());
        }
    }

    @LuaFunction
    public final boolean rsaVerify(String value, String signature, String publicKey) throws LuaException {
        // Implement RSA encryption logic here
        // This is a placeholder implementation

        try {
            return verify(value, signature, publicKey);
        } catch (Exception e) {
            throw new LuaException("Failed to verify signature: " + e.getMessage());
        }
    }

    @LuaFunction
    public final String rsaSign(String value, String privateKey) throws LuaException {
        // Implement RSA decryption logic here
        // This is a placeholder implementation

        try {
            return sign(value, privateKey);
        } catch (Exception e) {
            throw new LuaException("Failed to sign: " + e.getMessage());
        }
    }

    @LuaFunction
    public final String sha256(String value) throws LuaException {
        // Implement SHA-256 hashing logic here
        // This is a placeholder implementation
        try {
            return sha(value);
        } catch (Exception e) {
            throw new LuaException("Failed to sha256: " + e.getMessage());
        }
    }

    private static String encrypt(String data, String publicKey) throws Exception {
        Key key = getPublicKeyFromBase64(publicKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt data using a private RSA key.
     */
    private static String decrypt(String value, String privateKey) throws Exception {
        Key key = getPrivateKeyFromBase64(privateKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(value));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static String sign(String data, String privateKey) throws Exception {
        Key key = getPrivateKeyFromBase64(privateKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static boolean verify(String value, String signature, String publicKey) throws Exception {
        Key key = getPublicKeyFromBase64(publicKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(signature));
        return (new String(decrypted, StandardCharsets.UTF_8)).equals(value);
    }

    private static String sha(String input) throws Exception {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes("UTF-8"));

            // Convert bytes to hex string
            StringBuilder hexString = new StringBuilder(2 * hashBytes.length);
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();

        } catch (Exception e) {
            throw new Exception("Error computing SHA-256 hash", e);
        }
    }

    /**
     * Parse a Base64-encoded public key (X.509 format).
     */
    private static PublicKey getPublicKeyFromBase64(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(cleanPem(base64Key));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    /**
     * Parse a Base64-encoded private key (PKCS#8 format).
     */
    private static PrivateKey getPrivateKeyFromBase64(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(cleanPem(base64Key));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static String cleanPem(String pem) {
        return pem
                .replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)-----", "")
                .replaceAll("\\s+", "");  // removes all whitespace, including spaces and newlines
    }
}
