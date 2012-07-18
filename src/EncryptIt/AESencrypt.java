/*
 * Java encryption and decryption of data using AES algorithm
 */
package EncryptIt;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.*;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * This program will encode a string using the AES encryption cipher with a key
 * strength of 128 bits. It has been compiled based on references from the below
 * 2 sources and own time. I take no credit other than compiling, catching the
 * errors where necessary and updating where necessary.
 *
 * Sources:
 * http://www.code2learn.com/2011/06/encryption-and-decryption-of-data-using.html
 * http://java.sun.com/developer/technicalArticles/Security/AES/AES_v1.html
 *
 * @author Farhan Khwaja
 * @author Rags Srinivas
 * @author James Aylesworth
 */
public class AESencrypt {

    private static final String ALGORITHM = "AES";
    private static Key skey;

    public static String encrypt(String plainTextData) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException {
        skey = generateKey();
        Cipher theCipher = Cipher.getInstance(ALGORITHM);
        theCipher.init(Cipher.ENCRYPT_MODE, skey);
        byte[] encoderValue = theCipher.doFinal(plainTextData.getBytes());
        String encryptedData = new BASE64Encoder().encode(encoderValue);
        return encryptedData;
    }

    public static String decrypt(String encryptedData) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher theCipher = Cipher.getInstance(ALGORITHM);
        theCipher.init(Cipher.DECRYPT_MODE, skey);
        byte[] decoderValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decodeValue = theCipher.doFinal(decoderValue);
        String plainTextData = new String(decodeValue);
        return plainTextData;
    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(128);  //128, 192 or 256
        SecretKey theKey = keyGen.generateKey();
        return theKey;
    }

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);

        String someInputEncoded = "";
        String someInputDecoded = "";

        System.out.print("Please enter a string to encrypt:");
        String someInput = input.nextLine();
        try {
            someInputEncoded = AESencrypt.encrypt(someInput);
            someInputDecoded = AESencrypt.decrypt(someInputEncoded);
        } catch (InvalidKeyException | NoSuchAlgorithmException |
                NoSuchPaddingException | IllegalBlockSizeException |
                BadPaddingException | IOException e) {
            System.err.println("Exception caught: " + e.getMessage());
        }

        System.out.println("Plain Text: " + someInput);
        System.out.println("Key Used: " + skey.getEncoded());
        System.out.println("Encrypted: " + someInputEncoded);
        System.out.println("Decrypted: " + someInputDecoded);
    }
}
