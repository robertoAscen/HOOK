package hookCap3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Encriptacion.Utils;
import Encriptacion.PKCS5Scheme1;
import Encriptacion.MGF1;

public class hookCap3 {
	
	// Hombre en el medio con un criptograma AES y modo CTR
    public static void TamperedExample() throws Exception
	{
	   SecureRandom    random = new SecureRandom();
	   IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
	   Key             key = Utils.createKeyForAES(256, random);
	   Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
	   String          input = "Transfer 0000100 to AC 1234-5678";
	   System.out.println("input : " + input);
	   // encryption step
	   cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	   byte[] cipherText = cipher.doFinal(Utils.toByteArray(input));
	   // tampering step
	   System.out.println("cifrado : " + Utils.toHex(cipherText));
	   cipherText[9] ^= '0' ^ '9';
	   System.out.println("cifrado : " + Utils.toHex(cipherText));
	   // decryption step
	   cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	   byte[] plainText = cipher.doFinal(cipherText);
	   System.out.println("plain : " + Utils.toString(plainText));
	}

 // Hombre en el medio con un criptograma AES y modo CTR, invalidado por un message digest SHA-1
    public static void TamperedWithDigestExample() throws Exception
    {
        SecureRandom    random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          input = "Transfer 0000100 to AC 1234-5678";
        MessageDigest   hash = MessageDigest.getInstance("SHA-1", "BC");
        System.out.println("input : " + input);
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hash.getDigestLength())];
        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        hash.update(Utils.toByteArray(input));
        ctLength += cipher.doFinal(hash.digest(), 0, hash.getDigestLength(), cipherText, ctLength);
        // tampering step
        System.out.println("cifrado : " + Utils.toHex(cipherText));
        cipherText[9] ^= '0' ^ '9';
        System.out.println("cifrado : " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int    messageLength = plainText.length - hash.getDigestLength();
        hash.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[hash.getDigestLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        System.out.println("plain : " + Utils.toString(plainText, messageLength)
             + " verified: " + MessageDigest.isEqual(hash.digest(), messageHash));
    }
    
    // Hombre en el medio con un criptograma AES y modo CTR, con un message digest SHA-1 invalidado por man-in-the-middle
    public static void TamperedDigestExample() throws Exception
        {
            SecureRandom    random = new SecureRandom();
            IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
            Key             key = Utils.createKeyForAES(256, random);
            Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            String          input = "Transfer 0000100 to AC 1234-5678";
            MessageDigest   hash = MessageDigest.getInstance("SHA-1", "BC");
            System.out.println("input : " + input);
            // encryption step
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hash.getDigestLength())];
            int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
            hash.update(Utils.toByteArray(input));
            ctLength += cipher.doFinal(hash.digest(), 0, hash.getDigestLength(), cipherText, ctLength);
            // tampering step
            cipherText[9] ^= '0' ^ '9';
            // replace digest
            byte[] originalHash = hash.digest(Utils.toByteArray(input));
            byte[] tamperedHash = hash.digest(Utils.toByteArray("Transfer 9000100 to AC 1234-5678"));
            for (int i = ctLength - hash.getDigestLength(), j = 0; i != ctLength; i++, j++)
            {
                cipherText[i] ^= originalHash[j] ^ tamperedHash[j];
            }
            // decryption step
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
            int    messageLength = plainText.length - hash.getDigestLength();
            hash.update(plainText, 0, messageLength);
            byte[] messageHash = new byte[hash.getDigestLength()];
            System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
            System.out.println("plain : " + Utils.toString(plainText, messageLength)
                  + " verified: " + MessageDigest.isEqual(hash.digest(), messageHash));
        }
    
    // Hombre en el medio con un criptograma AES y modo CTR, invalidado por un HMAC SHA-1
    // En un HMAC, la clave secreta interviene en el hash
    public static void TamperedWithHMacExample() throws Exception
    {
        SecureRandom    random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          input = "Transfer 0000100 to AC 1234-5678";
        Mac             hMac = Mac.getInstance("HmacSHA1", "BC");
        Key             hMacKey = new SecretKeySpec(key.getEncoded(), "HmacSHA1");
        System.out.println("input : " + input);
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hMac.getMacLength())];
        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(input));
        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);
        // tampering step
        cipherText[9] ^= '0' ^ '9';
        // replace digest
        // ?
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int    messageLength = plainText.length - hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        System.out.println("plain : " + Utils.toString(plainText, messageLength) + " verified: " 
           + MessageDigest.isEqual(hMac.doFinal(), messageHash));
    }
    
    // Protecci�n de la integridad de un criptograma AES y modo CTR, con MAC(DES)
    public static void CipherMacExample() throws Exception
    {
        SecureRandom    random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          input = "Transfer 0000100 to AC 1234-5678";
        Mac             mac = Mac.getInstance("DES", "BC");
        byte[]          macKeyBytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        Key             macKey = new SecretKeySpec(macKeyBytes, "DES");
        System.out.println("input : " + input);
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];
        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        mac.init(macKey);
        mac.update(Utils.toByteArray(input));
        ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);
        //cipherText[9] ^= '0' ^ '9';
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int    messageLength = plainText.length - mac.getMacLength();
        mac.init(macKey);
        mac.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[mac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        System.out.println("plain : " + Utils.toString(plainText, messageLength) + " verified: " 
           + MessageDigest.isEqual(mac.doFinal(), messageHash));
    }

    // PBE con DES, en modo CBC, y SHA-1
    public static void PKCS5Scheme1Test() throws Exception
    {
            char[] password = "hello".toCharArray();
            byte[] salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
            byte[] input = new byte[] { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            int    iterationCount = 100;
            System.out.println("input : " + Utils.toHex(input));
            // encryption step using regular PBE
            Cipher           cipher = Cipher.getInstance("PBEWithSHA1AndDES","BC");
            SecretKeyFactory fact = SecretKeyFactory.getInstance("PBEWithSHA1AndDES", "BC");
            PBEKeySpec       pbeKeySpec = new PBEKeySpec(password, salt, iterationCount);
            cipher.init(Cipher.ENCRYPT_MODE, fact.generateSecret(pbeKeySpec));
            byte[] enc = cipher.doFinal(input);
            //enc[1] ^= '0' ^ '9';
            System.out.println("encrypt: " + Utils.toHex(enc));
            // decryption step - using the local implementation
            cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            PKCS5Scheme1 pkcs5s1 = new PKCS5Scheme1(MessageDigest.getInstance("SHA-1", "BC"));
            byte[] derivedKey = pkcs5s1.generateDerivedKey(password, salt, iterationCount);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivedKey, 0, 8, "DES"), 
            		new IvParameterSpec(derivedKey, 8, 8));
            byte[] dec = cipher.doFinal(enc);
            System.out.println("decrypt: " + Utils.toHex(dec));
    }
    
    // Enmascarando (ofuscando) un message digest
    public static void MaskGeneration() throws Exception
    {
        MGF1   mgf1 = new MGF1(MessageDigest.getInstance("SHA-1", "BC"));
        byte[] source = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        System.out.println(Utils.toHex(mgf1.generateMask(source, 20)));
    }

    
    public static void DigestIOExample() throws Exception
    {
       byte[] input = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 
    		   0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };;
       MessageDigest   hash = MessageDigest.getInstance("SHA1");
       System.out.println("input     : " + Utils.toHex(input));
       // input pass
       ByteArrayInputStream  bIn = new ByteArrayInputStream(input);
       DigestInputStream     dIn = new DigestInputStream(bIn, hash);
       ByteArrayOutputStream bOut = new ByteArrayOutputStream();
       int     ch;
       while ((ch = dIn.read()) >= 0)
       {
          bOut.write(ch);
       }
       byte[] newInput = bOut.toByteArray();
       System.out.println("in digest : " + Utils.toHex(dIn.getMessageDigest().digest()));
       // output pass
       bOut = new ByteArrayOutputStream();
       DigestOutputStream      dOut = new DigestOutputStream(bOut, hash);
       dOut.write(newInput);
       dOut.close();
       System.out.println("out digest: " + Utils.toHex(dOut.getMessageDigest().digest()));
    }

}
