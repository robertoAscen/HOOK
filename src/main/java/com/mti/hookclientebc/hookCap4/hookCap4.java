package hookCap4;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Encriptacion.Utils;

public class hookCap4 
{
    // Basic RSA
    public static void BaseRSAExample() throws Exception
    {	
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        // create the keys
        KeyFactory       keyFactory = KeyFactory.getInstance("RSA", "BC");
       /*RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16)); */
        // �Meti� las patas Hook?
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
        		new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
        		new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16)); 
        RSAPublicKey pubKey = (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = (RSAPrivateKey)keyFactory.generatePrivate(privKeySpec);
        System.out.println("input : " + Utils.toHex(input));
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    // Creating Random RSA Keys
    public static void RandomKeyRSAExample() throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        SecureRandom     random = new SecureRandom();
        //SecureRandom     random = Utils.createFixedRandom();
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048, random);
        //generator.initialize(128);
        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(input));
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }
	
    // Try It Out: PKCS #1 V1.5 Padding 
    public static void PKCS1PaddedRSAExample() throws Exception
    {
        byte[]           input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("RSA/None/PKCS1Padding","BC");
        SecureRandom     random = Utils.createFixedRandom();
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(256, random);
        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(input));
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }
    
    // OAEP Padding
    public static void OAEPPaddedRSAExample() throws Exception
    {
        byte[] input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };
        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        SecureRandom random = Utils.createFixedRandom();
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(386, random);
        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(input));
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }
    
    // Wrapping an RSA Private Key
    public static void AESWrapRSAExample() throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator fact = KeyPairGenerator.getInstance("RSA", "BC");
        fact.initialize(1024, random);
        KeyPair      keyPair = fact.generateKeyPair();
        Key          wrapKey = Utils.createKeyForAES(256, random);
        // wrap the RSA private key
        cipher.init(Cipher.WRAP_MODE, wrapKey);
        byte[] wrappedKey = cipher.wrap(keyPair.getPrivate());
        // unwrap the RSA private key
        cipher.init(Cipher.UNWRAP_MODE, wrapKey);
        Key key = cipher.unwrap(wrappedKey, "RSA", Cipher.PRIVATE_KEY);
        if (keyPair.getPrivate().equals(key))
            System.out.println("Key recovered.");
        else
            System.out.println("Key recovery failed.");
    }
    
    private static byte[] packKeyAndIv(Key key, IvParameterSpec ivSpec) throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());
        return bOut.toByteArray();
    }

    private static Object[] unpackKeyAndIV(byte[] data)
    {
        byte[]    keyD = new byte[16];
        byte[]    iv = new byte[data.length - 16];
        return new Object[] { new SecretKeySpec(data, 16, data.length - 16, "AES"), new IvParameterSpec(data, 0, 16) };
    }

    // Secret Key Exchange 
    public static void RSAKeyExchangeExample() throws Exception
    {
        byte[]           input = new byte[] { 0x00, (byte)0xbe, (byte)0xef };
        SecureRandom     random = Utils.createFixedRandom();
        // create the RSA Key
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024, random);
        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();
        System.out.println("input            : " + Utils.toHex(input));
        // create the symmetric key and iv
        Key             sKey = Utils.createKeyForAES(256, random);
        IvParameterSpec sIvSpec = Utils.createCtrIvForAES(0, random);
        // symmetric key/iv wrapping step
        Cipher           xCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        xCipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[]          keyBlock = xCipher.doFinal(packKeyAndIv(sKey, sIvSpec));
        // encryption step
        Cipher          sCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        sCipher.init(Cipher.ENCRYPT_MODE, sKey, sIvSpec);
        byte[] cipherText = sCipher.doFinal(input);
        System.out.println("keyBlock length  : " + keyBlock.length);
        System.out.println("cipherText length: " + cipherText.length);
        // symmetric key/iv unwrapping step
        xCipher.init(Cipher.DECRYPT_MODE, privKey);
        Object[]keyIv = unpackKeyAndIV(xCipher.doFinal(keyBlock));
        // decryption step
        sCipher.init(Cipher.DECRYPT_MODE, (Key)keyIv[0], (IvParameterSpec)keyIv[1]);
        byte[] plainText = sCipher.doFinal(cipherText);
        System.out.println("plain            : " + Utils.toHex(plainText));
    }
    
    private static BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7" 
        + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b" + "410b7a0f12ca1cb9a428cc", 16);
    private static BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
          + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b" + "f0573bf047a3aca98cdf3b", 16);

    // Diffie-Hellman Key Agreement 
    public static void BasicDHExample() throws Exception
    {
        DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(dhParams, Utils.createFixedRandom());
        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();
        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());
        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);
        //      generate the key bytes
        MessageDigest    hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());
        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }
    
    // Diffie-Hellman with Elliptic Curve
    public static void BasicECDHExample() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger(
            "fffffffffffffffffffffffffffffffeffffffffffffffff", 16)), 
            new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
            new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16));
        ECParameterSpec ecSpec = new ECParameterSpec(curve, new ECPoint(
            new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
            new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee", 16)),
            new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16), 1);
        keyGen.initialize(ecSpec, Utils.createFixedRandom());
        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();
        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());
        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);
        // generate the key bytes
        MessageDigest    hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());
        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }
    
    // Diffie-Hellman Three-Party Key Agreement 
    public static void BasicThreePartyDHExample() throws Exception
    {
        DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(dhParams, Utils.createFixedRandom());
        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      bPair = keyGen.generateKeyPair();
        KeyAgreement cKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair      cPair = keyGen.generateKeyPair();        
        // Three party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());
        cKeyAgree.init(cPair.getPrivate());
        // Como es un acuerdo de tres partes, es necesario generar tres llaves intermedias que seran usadas en el siguiente paso
        Key ac = aKeyAgree.doPhase(cPair.getPublic(), false);
        Key ba = bKeyAgree.doPhase(aPair.getPublic(), false);
        Key cb = cKeyAgree.doPhase(bPair.getPublic(), false);
        // Y ahora ya puedo generar el acuerdo entre tres
        aKeyAgree.doPhase(cb, true);
        bKeyAgree.doPhase(ac, true);
        cKeyAgree.doPhase(ba, true);
        // generate the key bytes
        MessageDigest    hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());
        byte[] cShared = hash.digest(cKeyAgree.generateSecret());
        System.out.println("Llave compartida por acuerdo, de Alice: " + Utils.toHex(aShared));
        System.out.println("Llave compartida por acuerdo, de Bob:   " + Utils.toHex(bShared));
        System.out.println("Llave compartida por acuerdo, de Carol: " + Utils.toHex(cShared));
    }
    
    // El Gamal example with random key generation
    public static void RandomKeyElGamalExample() throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        // create the keys
        generator.initialize(256, random);
        //generator.initialize(512, random);
        //generator.initialize(1024, random);
        //generator.initialize(2048, random);
        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(input));
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }
    
    // El Gamal Using AlgorithmParameterGenerator 
    public static void AlgorithmParameterExample() throws Exception
    {
        byte[]           input = new byte[] { (byte)0xbe, (byte)0xef };
        Cipher           cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        SecureRandom     random = Utils.createFixedRandom();
        // create the parameters
        AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("ElGamal", "BC");
        apg.init(256, random);
        AlgorithmParameters     params = apg.generateParameters();
        AlgorithmParameterSpec  dhSpec = params.getParameterSpec(DHParameterSpec.class);
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal", "BC");
        generator.initialize(dhSpec, random);
        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(input));
        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));
        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }
    
    // DSA Digital Signature Algorithm
    public static void BasicDSAExample() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "BC");
        keyGen.initialize(512, new SecureRandom());
        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("DSA", "BC");
        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());
        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        // Aqui se firma el mensaje
        signature.update(message);
        byte[] sigBytes = signature.sign();
        // verify a signature
        signature.initVerify(keyPair.getPublic());
                signature.update(message);
        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }
    
    // DSA with Elliptic Curve 
    // Simple example showing signature creation and verification using ECDSA
    public static void BasicECDSAExample() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        // Juego con el tamanio de las llaves, de 192 o 239 bits
        //ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime239v1");
        keyGen.initialize(ecSpec, new SecureRandom());
        KeyPair             keyPair = keyGen.generateKeyPair();
        Signature           signature = Signature.getInstance("ECDSA", "BC");
        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());
        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        signature.update(message);
        byte[] sigBytes = signature.sign();
        // verify a signature
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }
    
    // RSA Signature Generation 
    public static void PKCS1SignatureExample() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        //keyGen.initialize(512, new SecureRandom());
        // Necesita 1024 para SHA512
        keyGen.initialize(1024, new SecureRandom());
        KeyPair           keyPair = keyGen.generateKeyPair();
        //Signature         signature = Signature.getInstance("SHA1withRSA", "BC");
        //Signature         signature = Signature.getInstance("SHA224withRSA", "BC");
        //Signature         signature = Signature.getInstance("SHA256withRSA", "BC");
        Signature         signature = Signature.getInstance("SHA512withRSA", "BC");
        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());
        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        signature.update(message);
        byte[] sigBytes = signature.sign();
        // verify a signature
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        if (signature.verify(sigBytes))
        {
            System.out.println("signature verification succeeded.");
        }
        else
        {
            System.out.println("signature verification failed.");
        }
    }
    
}
