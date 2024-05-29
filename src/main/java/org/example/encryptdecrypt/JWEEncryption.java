package org.example.encryptdecrypt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class JWEEncryption {

    static RSAPublicKey  RsaPublicKey  = null;
   static RSAPrivateKey RsaPrivateKey = null;
    public static void createPrivatePublicKey() throws Exception {
      RSAKey keyPair =  generateRSAKeyPair();
        RsaPublicKey = keyPair.toRSAPublicKey();
        RsaPrivateKey = keyPair.toRSAPrivateKey();
    }


    public static void main(String[] args) throws Exception {
        // Generate RSA key pair (for demonstration purposes)
        RSAKey keyPair = generateRSAKeyPair();

        // Get private and public keys
        RSAPublicKey  RsaPublicKey = keyPair.toRSAPublicKey();
        RSAPrivateKey RsaPrivateKey = keyPair.toRSAPrivateKey();
        PrivateKey privateKey = keyPair.toPrivateKey();
        PublicKey publicKey = keyPair.toPublicKey();
        System.out.println("privateKey: " + RsaPrivateKey);
        System.out.println("publicKey: " + RsaPublicKey.getModulus());
        System.out.println("privateKey encoded " + encode(RsaPrivateKey.getEncoded()));
        System.out.println("publicKey encoded " + encode(RsaPublicKey.getEncoded()));

        // Data to be encrypted
        String dataToEncrypt = "Hello, world!";

        // Encrypt data using private key
        String encryptedData = encryptData(dataToEncrypt);

        // Decrypt data using public key
        String decryptedData = decryptData(encryptedData);

        System.out.println("Original Data: " + dataToEncrypt);
        System.out.println("Encrypted Data: " + encryptedData);
        System.out.println("Decrypted Data: " + decryptedData);
    }

    public static String encryptData(String data) throws Exception {
        //generate public key
        createPrivatePublicKey();
        // Create JWE header

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("text/plain")
                .build();

        // Create JWE object with payload
        JWEObject jweObject = new JWEObject(header, new Payload(data));

        // Create encrypter with the private key
        RSAEncrypter encrypter = new RSAEncrypter(RsaPublicKey);

        // Encrypt the payload
        jweObject.encrypt(encrypter);

        // Serialize to compact form
        return jweObject.serialize();
    }

    public static String decryptData(String encryptedData) throws Exception {
        // Parse the JWE object
        JWEObject jweObject = JWEObject.parse(encryptedData);

        // Create decrypter with the public key
        RSADecrypter decrypter = new RSADecrypter(RsaPrivateKey);

        // Decrypt the JWE object
        jweObject.decrypt(decrypter);

        // Extract payload
        return jweObject.getPayload().toString();
    }

    public static RSAKey generateRSAKeyPair() throws Exception {
        // Generate an RSA key pair with a key size of 2048 bits
        return new RSAKeyGenerator(2048).generate();
    }


    public static String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
}
