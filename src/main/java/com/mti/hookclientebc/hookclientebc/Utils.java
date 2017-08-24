package Encriptacion;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
/*import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage; */
import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.extension.*;

public class Utils 
{
    private static String digits = "0123456789abcdef";
    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
    public static String ROOT_ALIAS = "root";
    public static String INTERMEDIATE_ALIAS = "intermediate";
    public static String END_ENTITY_ALIAS = "end";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer    buf = new StringBuffer();
        for (int i = 0; i != length; i++)
        {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }

    /**
     * Create a key for use with AES.
     *
     * @param bitLength
     * @param random
     * @return a SecretKey of requested bitLength
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(int bitLength, SecureRandom random)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(256, random);
        return generator.generateKey();
    }

    /**
     * Create an IV suitable for using with AES in CTR mode.
     * <p>
     * The IV will be composed of 4 bytes of message number,
     * 4 bytes of random data, and a counter of 8 bytes.
     *
     * @param messageNumber the number of the message.
     * @param random a source of randomness
     * @return an initialised IvParameterSpec
     */
    public static IvParameterSpec createCtrIvForAES(int messageNumber, SecureRandom random)
    {
        byte[]          ivBytes = new byte[16];
        // initially randomize
        random.nextBytes(ivBytes);
        // set the message number bytes
        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);
        // set the counter bytes to 1
        for (int i = 0; i != 7; i++)
        {
            ivBytes[8 + i] = 0;
        }
        ivBytes[15] = 1;
        return new IvParameterSpec(ivBytes);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes, int length)
    {
        char[] chars = new char[length];
        for (int i = 0; i != chars.length; i++)
        {
            chars[i] = (char)(bytes[i] & 0xff);
        }
        return new String(chars);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(byte[] bytes)
    {
        return toString(bytes, bytes.length);
    }

    /**
     * Convert the passed in String to a byte array by
     * taking the bottom 8 bits of each character it contains.
     *
     * @param string the string to be converted
     * @return a byte array representation
     */
    public static byte[] toByteArray(String string)
    {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();
        for (int i = 0; i != chars.length; i++)
        {
            bytes[i] = (byte)chars[i];
        }
        return bytes;
    }
    
    private static class FixedRand extends SecureRandom
    {
        MessageDigest   sha;
        byte[]           state;
        FixedRand()
        {
            try
            {
                this.sha = MessageDigest.getInstance("SHA-1", "BC");
                this.state = sha.digest();
            }
            catch (Exception e)
            {
                throw new RuntimeException("can't find SHA-1!");
            }
        }

        public void nextBytes(
            byte[] bytes)
        {
            int off = 0;
            sha.update(state);
            while (off < bytes.length)
            {
                state = sha.digest();
                if (bytes.length - off > state.length)
                {
                    System.arraycopy(state, 0, bytes, off, state.length);
                }
                else
                {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }
                off += state.length;
                sha.update(state);
            }
        }
    }

    /**
     * Return a SecureRandom which produces the same value.
     * <b>This is for testing only!</b>
     * @return a fixed random
     */
    public static SecureRandom createFixedRandom()
    {
        return new FixedRand();
    }
    
    public static KeyPair generateRSAKeyPair() throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024, new SecureRandom());
        return kpGen.generateKeyPair();
    }
    
    /**
     * Generate a sample V1 certificate to use as a CA root certificate
     */
    public static X509Certificate generateRootCert(KeyPair pair) throws Exception
    {
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
        return certGen.generateX509Certificate(pair.getPrivate(), "BC");
    }
    
    /**
     * Generate a sample V3 certificate to use as an intermediate CA certificate
     */
    public static X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
       throws Exception
    {
       X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
       certGen.setSerialNumber(BigInteger.valueOf(1));
       certGen.setIssuerDN(caCert.getSubjectX500Principal());
       certGen.setNotBefore(new Date(System.currentTimeMillis()));
       certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
       certGen.setSubjectDN(new X500Principal("CN=Test Intermediate Certificate"));
       certGen.setPublicKey(intKey);
       certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
       certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
       certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(intKey));
       certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
       certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | 
    		   KeyUsage.cRLSign));
       return certGen.generateX509Certificate(caKey, "BC");
    }

    /**
     * Generate a sample V3 certificate to use as an end entity certificate
     */
    public static X509Certificate generateEndEntityCert(PublicKey entityKey, PrivateKey caKey, X509Certificate caCert)
       throws Exception
    {
       X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
       certGen.setSerialNumber(BigInteger.valueOf(1));
       certGen.setIssuerDN(caCert.getSubjectX500Principal());
       certGen.setNotBefore(new Date(System.currentTimeMillis()));
       certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
       certGen.setSubjectDN(new X500Principal("CN=Test End Certificate"));
       certGen.setPublicKey(entityKey);
       certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
       certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
       certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(entityKey));
       certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
       certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
       return certGen.generateX509Certificate(caKey, "BC");
    }
    
    /**
     * Generate a X500PrivateCredential for the root entity.
     */
    public static X500PrivateCredential createRootCredential() throws Exception
    {
        KeyPair rootPair = generateRSAKeyPair();
        X509Certificate rootCert = generateRootCert(rootPair);
        return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
    }

    /**
     * Generate a X500PrivateCredential for the intermediate entity.
     */
    public static X500PrivateCredential createIntermediateCredential(PrivateKey caKey, X509Certificate caCert) throws Exception
    {
         KeyPair interPair = generateRSAKeyPair();
         X509Certificate interCert = generateIntermediateCert(interPair.getPublic(), caKey, caCert);
         return new X500PrivateCredential(interCert, interPair.getPrivate(), INTERMEDIATE_ALIAS);
    }
    
    /**
     * Generate a X500PrivateCredential for the end entity.
     */
    public static X500PrivateCredential createEndEntityCredential(PrivateKey caKey, X509Certificate caCert) throws Exception
    {
        KeyPair endPair = generateRSAKeyPair();
        X509Certificate endCert = generateEndEntityCert(endPair.getPublic(), caKey, caCert);
        return new X500PrivateCredential(endCert, endPair.getPrivate(), END_ENTITY_ALIAS);
    }
        
    public static char[] KEY_PASSWD = "keyPassword".toCharArray();

    /**
     * Create a KeyStore containing the a private credential with
     * certificate chain and a trust anchor.
     */
    public static KeyStore createCredentials() throws Exception
    {
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);
        X500PrivateCredential rootCredential = Utils.createRootCredential();
        X500PrivateCredential interCredential = Utils.createIntermediateCredential(
        		rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential endCredential = Utils.createEndEntityCredential(
                 interCredential.getPrivateKey(), interCredential.getCertificate());
        store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
        store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), KEY_PASSWD,
              new Certificate[] { endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate()});
        return store;
     } 
     
    /**
      * Build a path using the given root as the trust anchor, and the passed
      * in end constraints and certificate store.
      * Note: the path is built with revocation checking turned off.
      */
     public static PKIXCertPathBuilderResult buildPath(X509Certificate rootCert, X509CertSelector endConstraints, 
    		 CertStore certsAndCRLs) throws Exception
     {
         CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
         PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(
        		 new TrustAnchor(rootCert, null)), endConstraints);
         buildParams.addCertStore(certsAndCRLs);
         buildParams.setRevocationEnabled(false);
         return (PKIXCertPathBuilderResult)builder.build(buildParams);
     }
     
     public static void Parte128bits(byte[] data, byte[] parte1, byte[] parte2)
     {
         for (int i = 0; i != 16; i++)
             parte1[i] = data[i];
         for (int i = 16; i != 32; i++)
         	parte2[i-16] = data[i];
     }

     /**
      * Create a MIME message from using the passed-in content.
      */
  /*   public static MimeMessage createMimeMessage(String subject, Object content, String contentType) throws MessagingException
     {
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);
        Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
        Address toUser = new InternetAddress("example@bouncycastle.org");
        MimeMessage message = new MimeMessage(session);
        message.setFrom(fromUser);
        message.setRecipient(Message.RecipientType.TO, toUser);
        message.setSubject(subject);
        message.setContent(content, contentType);
        message.saveChanges();
        return message;
     } */
}