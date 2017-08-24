package protocolos;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.zip.CRC32;
import java.util.zip.Checksum;

import Encriptacion.Utils;

public class Protocolos 
{
	/*
	 * 
	 *  Protocolos asimetricos
	 *  
	 */
	public static void ProtocoloConfidencialidadRSA() throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");

        SecureRandom     arandom = Utils.createFixedRandom();
        SecureRandom     brandom = Utils.createFixedRandom();
        
        // create the keys
        KeyPairGenerator agenerator = KeyPairGenerator.getInstance("RSA", "BC");
        KeyPairGenerator bgenerator = KeyPairGenerator.getInstance("RSA", "BC");

        agenerator.initialize(2048, arandom);
        bgenerator.initialize(2048, brandom);
        //agenerator.initialize(1024, arandom);
        //bgenerator.initialize(1024, brandom);
        //agenerator.initialize(128);
        //bgenerator.initialize(128);
        
        KeyPair          apair = agenerator.generateKeyPair();
        Key              apubKey = apair.getPublic();
        Key              aprivKey = apair.getPrivate();
        
        KeyPair          bpair = bgenerator.generateKeyPair();
        Key              bpubKey = bpair.getPublic();
        Key              bprivKey = bpair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, bpubKey, brandom);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // Alice envia el criptograma cipherText a Bob
        
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, bprivKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

	public static void ProtocoloAutenticacionRSA() throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        SecureRandom     random = Utils.createFixedRandom();
       
        // create the keys
        KeyPairGenerator agenerator = KeyPairGenerator.getInstance("RSA", "BC");
        KeyPairGenerator bgenerator = KeyPairGenerator.getInstance("RSA", "BC");

        //generator.initialize(1024, random);
        agenerator.initialize(128);
        bgenerator.initialize(128);
        
        KeyPair          apair = agenerator.generateKeyPair();
        Key              apubKey = apair.getPublic();
        Key              aprivKey = apair.getPrivate();
        
        KeyPair          bpair = bgenerator.generateKeyPair();
        Key              bpubKey = bpair.getPublic();
        Key              bprivKey = bpair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        // Esto lo hace Alice
        cipher.init(Cipher.ENCRYPT_MODE, aprivKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // Alice envia el criptograma de autenticacion a Bob
        
        // Esto lo hace Bob
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, apubKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }
	
	public static boolean EqualsByteArrays(byte[] A1, byte[] A2)
	{
		if(A1.length != A2.length)
			return false;
		for(int i = 0; i != A1.length; i++)
			if(A1[i] != A2[i])
				return false;
		return true;
	}
	
	public static void ProtocoloConfidencencialidadAutenticacionIntegridadRSAHash() throws Exception
    {
        Cipher           cipher = Cipher.getInstance("RSA", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        //String           input = "Transfer 12345";

        // create the keys
        KeyPairGenerator agenerator = KeyPairGenerator.getInstance("RSA", "BC");
        KeyPairGenerator bgenerator = KeyPairGenerator.getInstance("RSA", "BC");

        agenerator.initialize(1024, random);
        bgenerator.initialize(1024, random);
        
        KeyPair          apair = agenerator.generateKeyPair();
        Key              apubKey = apair.getPublic();
        Key              aprivKey = apair.getPrivate();
        
        KeyPair          bpair = bgenerator.generateKeyPair();
        Key              bpubKey = bpair.getPublic();
        Key              bprivKey = bpair.getPrivate();
        
        // 1. Alice calcula hash del mensaje 
        System.out.println("Comienza Alice");
        //int mihashcode = input.hashCode();
        //int alicehashcode = input.toString().hashCode();
        System.out.println("input en hexa: " + Utils.toHex(input));
        //System.out.println("input.toString().hashCode(): " + input.toString().hashCode());
        Checksum checksum = new CRC32();
        checksum.update(input,0,input.length);
        long alicecrc32 = checksum.getValue();
        
        // 2. Alice firma el hash con su llave privada
        cipher.init(Cipher.ENCRYPT_MODE, aprivKey, random);
        //byte[] cipherHash = cipher.doFinal(Utils.toByteArray(Integer.toString(mihashcode)));
        //System.out.println("Integer.toString(mihashcode) " + Integer.toString(mihashcode)); 
        byte[] cipherHash = cipher.doFinal(Utils.toByteArray(Long.toString(alicecrc32)));
        System.out.println("Long.toString(alicecrc32) " + Long.toString(alicecrc32)); 
        System.out.println("cipherhash: " + Utils.toHex(cipherHash)); 
        
        // 3. Alice cifra el mensaje con la llave publica de Bob
        cipher.init(Cipher.ENCRYPT_MODE, bpubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipherText: " + Utils.toHex(cipherText));
        
        // 4. Alice envia cipherHash y cipherText a Bob
        System.out.println("Termina Alice");
                
        // Mallory modifica cipherText
        //cipherText[3] ^= '0' ^ '9';
        System.out.println("cipherText: " + Utils.toHex(cipherText));
        
        // 5. Bob descifra cipherText usando RSA y su propia clave privada, para obtener el mensaje
        System.out.println("Comienza Bob");
        cipher.init(Cipher.DECRYPT_MODE, bprivKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plainText : " + Utils.toHex(plainText)); 
        
        // 6. Bob calcula el valor hash de M, h(M)
        //int segundohashcode = plainText.toString().hashCode();
        //System.out.println("plainText.hashCode() : " + segundohashcode);
        Checksum bobchecksum = new CRC32();
        bobchecksum.update(plainText,0,plainText.length);
        long bobcrc32 = bobchecksum.getValue();
        System.out.println("Long.toString(bobcrc32) " + Long.toString(bobcrc32)); 
        
        // 7. Bob descifra cipherHash usando RSA y la clave publica de Alice para obtener el h(M) que gener� Alice en el paso 1
        cipher.init(Cipher.DECRYPT_MODE, apubKey);
        byte[] plainHash = cipher.doFinal(cipherHash);
        
        // 8. Bob compara los resultados hash. El que Bob calculo con el que recibio de Alice
        byte[] bobByteArray = Utils.toByteArray(Long.toString(bobcrc32));
        if(EqualsByteArrays(plainHash,bobByteArray))
        	System.out.println("El hash ha sido firmado por Alice");
        else
        	System.out.println("El hash no ha sido firmado por Alice");
        System.out.println("Termina Bob");  
        System.out.println("TBD: Se esta usando CRC como funcion hash. No es segura");
    }
	
	// Protocolo de Confidencialidad y Autenticacion con AES
	public static void ProtocoloConfidencialidadAutenticacionAES() throws Exception
	{
        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] ivBytes = new byte[] { 
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        Cipher          cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
        KeyGenerator    generator = KeyGenerator.getInstance("AES", "BC");
        //generator.init(128);
        //generator.init(192);
        generator.init(256);
        Key encryptionKey = generator.generateKey();
        System.out.println("key :       " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("input :     " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipherText: " + Utils.toHex(cipherText));
        // create our decryption key using information
        // extracted from the encryption key
        Key    decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain :     " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
	}
	
	// Protocolo de Confidencialidad y Autenticacion con Triple Des
	public static void ProtocoloConfidencialidadAutenticacionTripleDes() throws Exception
	{
        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] ivBytes = new byte[] { 
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07 };
        Cipher          cipher = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
        KeyGenerator    generator = KeyGenerator.getInstance("DESede", "BC");
        //generator.init(128);
        //generator.init(192);
        Key encryptionKey = generator.generateKey();
        System.out.println("key :       " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("input :     " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipherText: " + Utils.toHex(cipherText));
        // create our decryption key using information
        // extracted from the encryption key
        Key    decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain :     " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
	}
	
	// Protocolo de Confidencialidad y Autenticacion con Des
	public static void ProtocoloConfidencialidadAutenticacionDes() throws Exception
	{
        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] ivBytes = new byte[] { 
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07 };
        Cipher          cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        KeyGenerator    generator = KeyGenerator.getInstance("DES", "BC");
        generator.init(64);
        Key encryptionKey = generator.generateKey();
        System.out.println("key :       " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("input :     " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipherText: " + Utils.toHex(cipherText));
        // create our decryption key using information
        // extracted from the encryption key
        Key    decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain :     " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
	}
	
	// Protocolo de Confidencialidad y Autenticacion con Blowfish
	public static void ProtocoloConfidencialidadAutenticacionBlowfish() throws Exception
	{
        byte[] input = new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] ivBytes = new byte[] { 
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07 };
        Cipher          cipher = Cipher.getInstance("Blowfish/CBC/NoPadding", "BC");
        KeyGenerator    generator = KeyGenerator.getInstance("Blowfish", "BC");
        //generator.init(64);
        //generator.init(128);
        //generator.init(192);
        //generator.init(256);
        //generator.init(512);
        //generator.init(1024);
        generator.init(2048);
        Key encryptionKey = generator.generateKey();
        System.out.println("key : " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("input :     " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipherText: " + Utils.toHex(cipherText));
        // create our decryption key using information
        // extracted from the encryption key
        Key    decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain :     " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }
}