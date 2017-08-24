package hookCap8;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.x509.X509V1CertificateGenerator;

import Encriptacion.Utils;

public class hookCap8 
{
   public static char[] keyPassword = "keyPassword".toCharArray();
   public static char[] keyPasswordEnd = "endPassword".toCharArray();
   public static char[] secretKeyPassword = "secretPassword".toCharArray();
   
   public static String ROOT_ALIAS = "root";

   public static KeyStore createKeyStore() throws Exception
   {
	  KeyStore store = KeyStore.getInstance("JKS");
      // initialize
	  store.load(null, null);
      X500PrivateCredential rootCredential = Utils.createRootCredential();
      X500PrivateCredential interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
	  X500PrivateCredential endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
      Certificate[] chain = new Certificate[3];
      chain[0] = endCredential.getCertificate();
      chain[1] = interCredential.getCertificate();
      chain[2] = rootCredential.getCertificate();
      // set the entries
      store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
	  store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), keyPassword, chain);
	  return store;
   }

   // Example of basic use of KeyStore
   public static void JKSStoreExample() throws Exception
   {
	  KeyStore store = createKeyStore();
	  char[]   password = "storePassword".toCharArray();
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      // save the store
      store.store(bOut, password);
      // reload from scratch
      store = KeyStore.getInstance("JKS");
      store.load(new ByteArrayInputStream(bOut.toByteArray()), password);
      Enumeration en = store.aliases();
      while (en.hasMoreElements())
      {
         String alias = (String)en.nextElement();
         System.out.println("found " + alias + ", isCertificate? " + store.isCertificateEntry(alias));
	  }
   }
   
   public static KeyStore createKeyStoreJCEKS() throws Exception
   {
	  KeyStore store = KeyStore.getInstance("JCEKS");
      // initialize
	  store.load(null, null);
      X500PrivateCredential rootCredential = Utils.createRootCredential();
      X500PrivateCredential interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
	  X500PrivateCredential endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
	  Certificate[] chain = new Certificate[3];
      chain[0] = endCredential.getCertificate();
      chain[1] = interCredential.getCertificate();
      chain[2] = rootCredential.getCertificate();
      SecretKey secret = Utils.createKeyForAES(256, new SecureRandom());
      // set the entries
      store.setEntry(rootCredential.getAlias(), new KeyStore.TrustedCertificateEntry(rootCredential.getCertificate()), null);
	  store.setEntry(endCredential.getAlias(), new KeyStore.PrivateKeyEntry(endCredential.getPrivateKey(), chain), 
			  new KeyStore.PasswordProtection(keyPasswordEnd));
	  store.setEntry("secret", new KeyStore.SecretKeyEntry(secret), new KeyStore.PasswordProtection(secretKeyPassword));
      return store;
   }

   // Example of using a JCEKS keystore with KeyStore.Entry and KeyStore.ProtectionParameter objects
   public static void JCEKSStoreEntryExample() throws Exception
   {
	  KeyStore store = createKeyStoreJCEKS();
      char[] password = "storePassword".toCharArray();
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      // save the store
	  store.store(bOut, password);
      // reload from scratch
	  store = KeyStore.getInstance("JCEKS");
      store.load(new ByteArrayInputStream(bOut.toByteArray()), password);
      Enumeration en = store.aliases();
	  while (en.hasMoreElements())
	  {
         String alias = (String)en.nextElement();
	     System.out.println("found " + alias + ", isCertificate? " + store.isCertificateEntry(alias) + ", secret key entry? " 
            + store.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class));
	  }
   }
   
   // Basic example of use of KeyStore.Builder to create an object that can be used recover a private key
   public static void JCEKSStoreBuilderExample() throws Exception
   {
      KeyStore store = createKeyStoreJCEKS();
      char[] password = "storePassword".toCharArray();
      // create the builder
      KeyStore.Builder builder = KeyStore.Builder.newInstance(store, new KeyStore.PasswordProtection(keyPasswordEnd));
      // use the builder to recover the KeyStore and obtain the key
      store = builder.getKeyStore();
      KeyStore.ProtectionParameter param = builder.getProtectionParameter(Utils.END_ENTITY_ALIAS);
      KeyStore.Entry entry = store.getEntry(Utils.END_ENTITY_ALIAS, param);
      System.out.println("recovered " + entry.getClass());
   }
   
   public static KeyStore createKeyStorePKCS12() throws Exception
   {
      KeyStore store = KeyStore.getInstance("PKCS12", "BC");
      // initialize
      store.load(null, null);
      X500PrivateCredential rootCredential = Utils.createRootCredential();
      X500PrivateCredential interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
	  X500PrivateCredential endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
	  Certificate[] chain = new Certificate[3];
      chain[0] = endCredential.getCertificate();
      chain[1] = interCredential.getCertificate();
      chain[2] = rootCredential.getCertificate();
      // set the entries
      store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
      store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), null, chain);
      return store;
   }
   
   public static X509Certificate generateRootCert(KeyPair pair) throws Exception
   {
       X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
       certGen.setSerialNumber(BigInteger.valueOf(1));
       certGen.setIssuerDN(new X500Principal("CN=SERGIO ELLERBRACKE, L=GUADALAJARA, ST=JALISCO, O=UNIVA, C=MEXICO"));
       certGen.setNotBefore(new Date(System.currentTimeMillis()));
       certGen.setNotAfter(new Date(System.currentTimeMillis() + 999999999));
       certGen.setSubjectDN(new X500Principal("CN=Test CA Certificate"));
       certGen.setPublicKey(pair.getPublic());
       certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
       return certGen.generateX509Certificate(pair.getPrivate(), "BC");
   }
   
   public static X500PrivateCredential createRootCredential(KeyPair rootPair) throws Exception
   {
       X509Certificate rootCert = generateRootCert(rootPair);
       return new X500PrivateCredential(rootCert, rootPair.getPrivate(), ROOT_ALIAS);
   }
   
   public static KeyStore createKeyStorePKCS12(KeyPair rootPair) throws Exception
   {
       KeyStore store = KeyStore.getInstance("PKCS12", "BC");
	   // initialize
	   store.load(null, null);
	   //X509Certificate rootCert = generateRootCert(rootPair);
	   X500PrivateCredential rootCredential = createRootCredential(rootPair);
	   Certificate[] chain = new Certificate[1];
       chain[0] = rootCredential.getCertificate();
       store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
       store.setKeyEntry(rootCredential.getAlias(), rootCredential.getPrivateKey(), null, chain);
       return store;
   }

   // Using a PKCS #12 Keystore 
   public static void PKCS12StoreExample() throws Exception
   {
	  KeyStore store = createKeyStorePKCS12();
	  char[] password = "storePassword".toCharArray();
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      store.store(bOut, password);
      store = KeyStore.getInstance("PKCS12", "BC");
      store.load(new ByteArrayInputStream(bOut.toByteArray()), password);
      Enumeration en = store.aliases();
      while (en.hasMoreElements())
      {
	     String alias = (String)en.nextElement();
	     System.out.println("found " + alias + ", isCertificate? " + store.isCertificateEntry(alias));
      }
   }

   // No genera bien el keystore.jks
   // Create some keystore files in the current directory
   public static void KeyStoreFileUtility() throws Exception
   {
	  char[] password = "storePassword".toCharArray();
      // create and save a JKS store
      KeyStore store = createKeyStoreJCEKS();
      store.store(new FileOutputStream("keystore.jks"), password);
      // create and save a PKCS #12 store
	  store = createKeyStorePKCS12();
	  store.store(new FileOutputStream("keystore.p12"), password);
   }
   
   

}
