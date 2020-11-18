import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Fury AES Encryption utility class */
public class AESUtil {


  public static void main(String[] arguments) {
      String mode = arguments[0];
      String valueToBeEncrypted = arguments[1];
      switch (mode) {
          case "encrypt":
              System.out.println(encrypt(valueToBeEncrypted));
              break;
          case "decrypt":
              System.out.println(decrypt(valueToBeEncrypted));
              break;
          default:
              System.out.println("Fuck you!!");
      }
  }

  private static final int GCM_IV_LENGTH = 12;
  private static final int GCM_TAG_LENGTH = 16;
  private static final String algorithm = "AES/GCM/PKCS5PADDING";

  private static String encryptionKey = "5RF1E9TU-V02H-78WS-0RU4-2900XMK3";

  /**
   * Encrypt the given string using AES-GCM algorithm
   *
   * @param value to be encrypted
   * @return encrypted string
   */
  public static String encrypt(String value) {
    try {
      byte[] initializationVector = getInitializationVector();
      SecretKey secretKey = getSecretKey();
      GCMParameterSpec ivSpec = getGCMParameterSpec(initializationVector);
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
      byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
      encrypted = getAlteredEncryptedValue(initializationVector, encrypted);
      return Base64.getEncoder().encodeToString(encrypted);
    } catch (NoSuchAlgorithmException
        | NoSuchPaddingException
        | InvalidAlgorithmParameterException
        | InvalidKeyException
        | BadPaddingException
        | IllegalBlockSizeException e) {
      System.out.println("Exception occurred while encrypting: " + e.getMessage());
    }
    return null;
  }

  /**
   * Decrypt the encrypted string using AES-GCM algorithm
   *
   * @param encrypted string
   * @return decrypted string
   */
  public static String decrypt(String encrypted) {
    try {
      byte[] decoded = Base64.getDecoder().decode(encrypted);
      GCMParameterSpec ivSpec = getGCMParameterSpecFromEncryptedArray(decoded);
      SecretKey secretKey = getSecretKey();
      Cipher cipher = Cipher.getInstance(algorithm);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
      byte[] decrypted = cipher.doFinal(decoded, GCM_IV_LENGTH, decoded.length - GCM_IV_LENGTH);
      return new String(decrypted, StandardCharsets.UTF_8);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | NoSuchPaddingException
        | BadPaddingException
        | IllegalBlockSizeException e) {
      System.out.println("Exception occurred while decrypting: " + e.getMessage());
    }
    return null;
  }

  /*
     Generates a secret key from an encryption string using AES algorithm
  */
  private static SecretKey getSecretKey() {
    return new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), "AES");
  }

  /*
     Generates an initialization vector with Standard GCM IV Length
  */
  private static byte[] getInitializationVector() {
    byte[] initializationVector = new byte[GCM_IV_LENGTH];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(initializationVector);
    return initializationVector;
  }

  /*
     Generates GCMParameterSpec from a given byte array and Standard GCM Tag Length
  */
  private static GCMParameterSpec getGCMParameterSpec(byte[] byteArray) {
    return new GCMParameterSpec(GCM_TAG_LENGTH * Byte.SIZE, byteArray);
  }

  /*
     Generates GCMParameterSpec from an encrypted byte array
  */
  private static GCMParameterSpec getGCMParameterSpecFromEncryptedArray(byte[] decoded) {
    byte[] iv = Arrays.copyOfRange(decoded, 0, GCM_IV_LENGTH);
    return getGCMParameterSpec(iv);
  }

  /*
     Alters an encrypted byte array with given IV
  */
  private static byte[] getAlteredEncryptedValue(byte[] initializationVector, byte[] encrypted) {
    byte[] altered = new byte[initializationVector.length + encrypted.length];
    System.arraycopy(initializationVector, 0, altered, 0, initializationVector.length);
    System.arraycopy(encrypted, 0, altered, initializationVector.length, encrypted.length);
    return altered;
  }
}
