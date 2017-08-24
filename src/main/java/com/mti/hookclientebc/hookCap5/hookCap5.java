package hookCap5;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import Encriptacion.Utils;

public class hookCap5 
{
   // Prueba MyStructure
   public static void MyStructureTest() throws Exception
   {
        byte[] baseData = new byte[5];
	Date created = new Date(0); // 1/1/1970
        MyStructure structure = new MyStructure(0, created, baseData, null, null);
        System.out.println(Utils.toHex(structure.getEncoded()));
         if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        structure = new MyStructure(0, created, baseData, "hello", null);
         System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        structure = new MyStructure(0, created, baseData, null, "world");
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        structure = new MyStructure(0, created, baseData, "hello", "world");
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
        structure = new MyStructure(1, created, baseData, null, null);
        System.out.println(Utils.toHex(structure.getEncoded()));
        if (!structure.equals(structure.toASN1Object()))
        {
            System.out.println("comparison failed.");
        }
   }
   
    // Example for ASN1Dump using MyStructure
    public static void ASN1DumpExample() throws Exception
    {
	byte[] baseData = new byte[5];
	Date created = new Date(0); // 1/1/1970
        MyStructure structure = new MyStructure(0, created, baseData, "hello", "world");
	System.out.println(ASN1Dump.dumpAsString(structure));
        structure = new MyStructure(1, created, baseData, "hello", "world");
        System.out.println(ASN1Dump.dumpAsString(structure));
        ASN1InputStream aIn = new ASN1InputStream(structure.getEncoded());
        System.out.println(ASN1Dump.dumpAsString(aIn.readObject()));
    }

    // Example showing IV encoding
    public static void IVExample() throws Exception
    {
        // set up the parameters object
        AlgorithmParameters params = AlgorithmParameters.getInstance("AES", "BC");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        params.init(ivSpec);
        // look at the ASN.1 encodng.
        ASN1InputStream aIn = new ASN1InputStream(params.getEncoded("ASN.1"));
        System.out.println(ASN1Dump.dumpAsString(aIn.readObject()));
    }

    // Basic class for exploring PKCS #1 V1.5 Signatures
    public static void PKCS1SigEncodingExample() throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
         keyGen.initialize(512, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        // generate a signature
        signature.initSign(keyPair.getPrivate());
        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };
        signature.update(message);
        byte[] sigBytes = signature.sign();
        // verify hash in signature
        Cipher    cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
        byte[] decSig = cipher.doFinal(sigBytes);
        // parse the signature
        ASN1InputStream aIn = new ASN1InputStream(decSig);
        ASN1Sequence     seq = (ASN1Sequence)aIn.readObject();
        System.out.println(ASN1Dump.dumpAsString(seq));
        // grab a digest of the correct type
        MessageDigest    hash = MessageDigest.getInstance("SHA-256", "BC");
        hash.update(message);
        ASN1OctetString sigHash = (ASN1OctetString)seq.getObjectAt(1);
        if (MessageDigest.isEqual(hash.digest(), sigHash.getOctets()))
        {
            System.out.println("hash verification succeeded");
        }
        else
        {
            System.out.println("hash verification failed");
        }
    }

    // Example showing PSS parameter recovery and encoding
    public static void PSSParamExample() throws Exception
    {
        Signature signature = Signature.getInstance("SHA1withRSAandMGF1", "BC");
        // set the default parameters
        signature.setParameter(PSSParameterSpec.DEFAULT);
        // get the default parameters
        AlgorithmParameters params = signature.getParameters();
        // look at the ASN.1 encodng.
        ASN1InputStream aIn = new ASN1InputStream(params.getEncoded("ASN.1"));
        System.out.println(ASN1Dump.dumpAsString(aIn.readObject()));
    }

    // Simple example showing use of X509EncodedKeySpec
    public static void X509EncodedKeySpecExample() throws Exception
    {
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(128, Utils.createFixedRandom());
        KeyPair              pair = generator.generateKeyPair();
        // dump public key
        ASN1InputStream aIn = new ASN1InputStream(pair.getPublic().getEncoded());
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(aIn.readObject());
        System.out.println(ASN1Dump.dumpAsString(info));
        System.out.println(ASN1Dump.dumpAsString(info.getPublicKey()));
        // create from specification
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pair.getPublic().getEncoded());
        KeyFactory         keyFact = KeyFactory.getInstance("RSA", "BC");
        PublicKey          pubKey = keyFact.generatePublic(x509Spec);
        if (pubKey.equals(pair.getPublic()))
        {
            System.out.println("key recovery successful");
        }
        else
        {
            System.out.println("key recovery failed");
        }
    }

    // Simple example showing how to use PBE and an EncryptedPrivateKeyInfo object
    public static void EncryptedPrivateKeyInfoExample() throws Exception
    {
        // generate a key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(128, Utils.createFixedRandom());
        KeyPair pair = kpg.generateKeyPair();
        // wrapping step
        char[]             password = "hello".toCharArray();
        byte[]             salt = new byte[20];
        int                iCount = 100;
        String             pbeAlgorithm = "PBEWithSHAAnd3-KeyTripleDES-CBC";
        PBEKeySpec         pbeKeySpec = new PBEKeySpec(password, salt, iCount);
        SecretKeyFactory   secretKeyFact = SecretKeyFactory.getInstance(pbeAlgorithm, "BC");
        Cipher             cipher = Cipher.getInstance(pbeAlgorithm, "BC");
        cipher.init(Cipher.WRAP_MODE, secretKeyFact.generateSecret(pbeKeySpec));
        byte[]             wrappedKey = cipher.wrap(pair.getPrivate());
        // create carrier
        EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(cipher.getParameters(), wrappedKey);
        // unwrapping step - note we only use the password
        pbeKeySpec = new PBEKeySpec(password);
        cipher = Cipher.getInstance(pInfo.getAlgName(), "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKeyFact.generateSecret(pbeKeySpec), pInfo.getAlgParameters());
        PKCS8EncodedKeySpec pkcs8Spec = pInfo.getKeySpec(cipher);
        KeyFactory          keyFact = KeyFactory.getInstance("RSA", "BC");
        PrivateKey          privKey = keyFact.generatePrivate(pkcs8Spec);
        if (privKey.equals(pair.getPrivate()))
        {
            System.out.println("key recovery successful");
        }
        else
        {
            System.out.println("key recovery failed");
        }
        System.out.println(ASN1Dump.dumpAsString(new ASN1InputStream(cipher.getParameters().getEncoded()).readObject()));
        ASN1InputStream      aIn = new ASN1InputStream(pkcs8Spec.getEncoded());
        PrivateKeyInfo       info = PrivateKeyInfo.getInstance(aIn.readObject());
        System.out.println(ASN1Dump.dumpAsString(info));
        System.out.println(ASN1Dump.dumpAsString(info.getPrivateKey()));
    }
}