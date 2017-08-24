package hookCap2;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Encriptacion.Utils;

public class hookCap2 
{
	// Encripta con AES y una llave alambrada
	public static void SimpleSymmetricExample() throws Exception
    {
        byte[] input = new byte[] {
                          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                          (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff };
        byte[] keyBytes = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher        cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        System.out.println("input text : " + Utils.toHex(input));
        // encryption pass
        byte[] cipherText = new byte[input.length];
        cipher.init(Cipher.ENCRYPT_MODE, key);
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        // decryption pass
        byte[] plainText = new byte[ctLength];
        cipher.init(Cipher.DECRYPT_MODE, key);
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain text : " + Utils.toHex(plainText) + " bytes: " + ptLength);
    }
	
	// Encripta con AES, una llave alambrada, y rellenando con PKCS7Padding
	public static void SimpleSymmetricPaddingExample() throws Exception
    {
        byte[] input = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        byte[] keyBytes = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain : " + Utils.toHex(plainText) + " bytes: " + ptLength);
    }
	
	// Encripta con DES, en modo ECB, llave alambrada
    public static void SimpleECBExample() throws Exception
    {
        byte[] input = new byte[] {
                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] keyBytes = new byte[] {
                           0x01, 0x23, 0x45, 0x67,
                           (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        Cipher        cipher = Cipher.getInstance("DES/ECB/PKCS7Padding", "BC");
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);
        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }

    // Encripta con DES, en modo CBC, llave alambrada
    public static void SimpleCBCExample() throws Exception
    {
        byte[] input = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] keyBytes = new byte[] {
                                0x01, 0x23, 0x45, 0x67,
                                (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        byte[] ivBytes = new byte[] { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
        SecretKeySpec   key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher          cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);
        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }
    
    // Encripta con DES, en modo CBC, con IV (Initialization Vector), llave alambrada
    public static void InlineIvCBCExample() throws Exception
    {
        byte[] input = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] keyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        byte[] ivBytes = new byte[] { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 };
        SecretKeySpec   key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[8]);
        Cipher          cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(ivBytes.length + input.length)];
        int ctLength = cipher.update(ivBytes, 0, ivBytes.length, cipherText, 0);
        ctLength += cipher.update(input, 0, input.length, cipherText, ctLength);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);
        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] buf = new byte[cipher.getOutputSize(ctLength)];
        int bufLength = cipher.update(cipherText, 0, ctLength, buf, 0);
        bufLength += cipher.doFinal(buf, bufLength);
        // remove the iv from the start of the message
        byte[] plainText = new byte[bufLength - ivBytes.length];
        System.arraycopy(buf, ivBytes.length, plainText, 0, plainText.length);
        System.out.println("plain : " + Utils.toHex(plainText, plainText.length) + " bytes: " + plainText.length);
    }
    
    // Encripta con DES, en modo CBC, con IV (Initialization Vector), semilla y llave alambrada
    public static void NonceIvCBCExample() throws Exception
    {
        byte[] input = new byte[] {
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] keyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        byte[] msgNumber = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        IvParameterSpec zeroIv = new IvParameterSpec(new byte[8]);
        SecretKeySpec   key = new SecretKeySpec(keyBytes, "DES");
        Cipher          cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        // generate IV
        cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);
        IvParameterSpec encryptionIv = new IvParameterSpec(cipher.doFinal(msgNumber), 0, 8);
        // encrypt message
        cipher.init(Cipher.ENCRYPT_MODE, key, encryptionIv);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);
        // decryption pass
        // generate IV
        cipher.init(Cipher.ENCRYPT_MODE, key, zeroIv);
        IvParameterSpec decryptionIv = new IvParameterSpec(cipher.doFinal(msgNumber), 0, 8);
        // decrypt message
        cipher.init(Cipher.DECRYPT_MODE, key, decryptionIv);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }
    
    // Encripta con DES, en modo CTR, llave alambrada
    public static void SimpleCTRExample() throws Exception
    {
        byte[] input = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
        byte[] keyBytes = new byte[] { 0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef };
        byte[] ivBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x01 };
        SecretKeySpec   key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher          cipher = Cipher.getInstance("DES/CTR/NoPadding", "BC");
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("cipher: " + Utils.toHex(cipherText, ctLength) + " bytes: " + ctLength);
        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }

    // Encripta con ARC4 (basado en RC4) y una llave alambrada 
    public static void SimpleStreamExample() throws Exception
    {
       byte[] input = new byte[] {
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                              (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff };
       byte[] keyBytes = new byte[] { 
                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
       SecretKeySpec key = new SecretKeySpec(keyBytes, "ARC4");
       Cipher        cipher = Cipher.getInstance("ARC4", "BC");
       System.out.println("input text : " + Utils.toHex(input));
       // encryption pass
       byte[] cipherText = new byte[input.length];
       cipher.init(Cipher.ENCRYPT_MODE, key);
       int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
       ctLength += cipher.doFinal(cipherText, ctLength);
       System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + ctLength);
       // decryption pass
       byte[] plainText = new byte[ctLength];
       cipher.init(Cipher.DECRYPT_MODE, key);
       int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
       ptLength += cipher.doFinal(plainText, ptLength);
       System.out.println("plain text : " + Utils.toHex(plainText) + " bytes: " + ptLength);
   }

    // Encripta con AES, en modo CTR, generando la llave
    public static void KeyGeneratorExample() throws Exception
    {
        byte[] input = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] ivBytes = new byte[] { 
                            0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        KeyGenerator    generator = KeyGenerator.getInstance("AES", "BC");
        //generator.init(128);
        //generator.init(192);
        generator.init(256);
        Key encryptionKey = generator.generateKey();
        System.out.println("key : " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        System.out.println("criptograma : " + Utils.toHex(cipherText));
        // create our decryption key using information
        // extracted from the encryption key
        Key    decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        byte[] plainText = new byte[cipher.getOutputSize(ctLength)];
        int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
        ptLength += cipher.doFinal(plainText, ptLength);
        System.out.println("plain : " + Utils.toHex(plainText, ptLength) + " bytes: " + ptLength);
    }
    
    /* C U I D A D O
 	   Provoca una excepci�n al desplegar System.out.println ("gen key: " + Utils.toHex(sKey.getEncoded()));
 	   pad block corrupted
 	   Era un c�digo que tra�a varios errores de sintaxis, en el Hook. */
    // Encripta con DESede y PBE (Password Based Encryption), llave alambrada
    // Provoca una excepci�n al desplegar ystem.out.println ("gen key: " + Utils.toHex(sKey.getEncoded()));
    public static void PBEWithParamsExample() throws Exception
    {
        byte[] input = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] keyBytes = new byte[] {
                            0x73, 0x2f, 0x2d, 0x33, (byte)0xc8, 0x01, 0x73,
                            0x2b, 0x72, 0x06, 0x75, 0x6c, (byte)0xbd, 0x44,
                            (byte)0xf9, (byte)0xcl, (byte)0xc1, 0x03, (byte)0xdd,
                            (byte)0xd9, 0x7c, 0x7c, (byte)0xbe, (byte)0x8e };
        byte[] ivBytes = new byte[] {
                            (byte)0xb0, 0x7b, (byte)0xf5, 0x22, (byte)0xc8,
                            (byte)0xd6, 0x08, (byte)0xb8 };
        // encrypt the data using precalculated keys
        Cipher cEnc = Cipher.getInstance ("DESede/CBC/PKCS7Padding", "BC");
        cEnc.init (Cipher.ENCRYPT_MODE,new SecretKeySpec(keyBytes, "DESede"),new IvParameterSpec(ivBytes));
        byte[] out =cEnc. doFinal(input);
        // decrypt the data using PBE
        char[] password = "password".toCharArray();
        byte[]  salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte)0xe0, (byte)0xae };
        int iterationCount = 2048;
        PBEKeySpec       pbeSpec = new PBEKeySpec(password);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Key    sKey = keyFact.generateSecret(pbeSpec);
        cDec.init(Cipher.DECRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
        System.out.println ("cipher : " + Utils.toHex(out)) ;
        System.out.println ("gen key: " + Utils.toHex(sKey.getEncoded()));
        System.out.println ("gen iv : " + Utils.toHex(cDec.getIV()));
        System.out.println ("plain  : " + Utils. toHex(cDec.doFinal(out)));
    }

    // Encripta con DESede y PBE (Password Based Encryption) sin usar PBEParameterSpec, llave alambrada
    public static void PBEWithoutParamsExample() throws Exception
    {

        byte[] input = new byte[] {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
        byte[] keyBytes = new byte[] {
                            0x73, 0x2f, 0x2d, 0x33, (byte)0xc8, 0x01, 0x73,
                            0x2b, 0x72, 0x06, 0x75, 0x6c, (byte)0xbd, 0x44,
                            (byte)0xf9, (byte)0xc1, (byte)0xc1, 0x03, (byte)0xdd,
                            (byte)0xd9, 0x7c, 0x7c, (byte)0xbe, (byte)0x8e };
        byte[] ivBytes = new byte[] { (byte)0xb0, 0x7b, (byte)0xf5, 0x22, (byte)0xc8, (byte)0xd6, 0x08, (byte)0xb8 };
        // encrypt the data using precalculated keys
        Cipher cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
        cEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"), new IvParameterSpec(ivBytes));
        byte[] out = cEnc.doFinal(input);
        // decrypt the data using PBE
        char[]             password = "password".toCharArray();
        byte[]             salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };
        int                iterationCount = 2048;
        PBEKeySpec         pbeSpec = new PBEKeySpec(password, salt, iterationCount);
        SecretKeyFactory   keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Key    sKey = keyFact.generateSecret(pbeSpec);
        cDec.init(Cipher.DECRYPT_MODE, sKey);
        System.out.println("cipher : " + Utils.toHex(out));
        System.out.println("gen key: " + Utils.toHex(sKey.getEncoded()));
        System.out.println("gen iv : " + Utils.toHex(cDec.getIV()));
        System.out.println("plain  : " + Utils.toHex(cDec.doFinal(out)));
    }

    // Envoltura de una llave AES
    public static void SimpleWrapExample() throws Exception
    {
        // create a key to wrap
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(128);
        Key    KeyToBeWrapped = generator.generateKey();
        System.out.println("key      : " + Utils.toHex(KeyToBeWrapped.getEncoded()));
        // create a wrapper and do the wrapping
        Cipher cipher = Cipher.getInstance("AESWrap", "BC");
        KeyGenerator KeyGen = KeyGenerator.getInstance("AES", "BC");
        KeyGen.init(256);
        Key wrapKey = KeyGen.generateKey();
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        byte[] wrappedKey = cipher.wrap(KeyToBeWrapped);
        System.out.println("wrapped  : " + Utils.toHex(wrappedKey));
        // unwrap the wrapped key
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        Key key = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
        System.out.println("unwrapped: " + Utils.toHex(key.getEncoded()));
    }

    // Usando Entrada y Salida segura, llave alambrada
    public static void SimpleIOExample() throws Exception
    {
       byte[] input = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
       byte[] keyBytes = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

       byte[] ivBytes = new byte[] {
                                0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
       SecretKeySpec   key = new SecretKeySpec(keyBytes, "AES");
       IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
       Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
       System.out.println("input : " + Utils.toHex(input));
       // encryption pass
       cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
       ByteArrayInputStream    bIn = new ByteArrayInputStream(input);
       CipherInputStream       cIn = new CipherInputStream(bIn, cipher);
       ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
       int ch;
       while ((ch = cIn.read()) >= 0)
       {
           bOut.write(ch);
       }
       byte[] cipherText = bOut.toByteArray();
       System.out.println("cipher: " + Utils.toHex(cipherText));
       // decryption pass
       cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
       bOut = new ByteArrayOutputStream();
       CipherOutputStream      cOut = new CipherOutputStream(bOut, cipher);
       cOut.write(cipherText);
       cOut.close();
       System.out.println("plain: " + Utils.toHex(bOut.toByteArray()));
    }
    
}
