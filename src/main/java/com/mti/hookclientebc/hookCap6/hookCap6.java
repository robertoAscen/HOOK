package hookCap6;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import Encriptacion.Utils;

public class hookCap6 
{
   // Try It Out: Creating a Self-Signed Version 1 Certificate 
   public static X509Certificate generateV1Certificate(KeyPair pair) 
		throws InvalidKeyException, NoSuchProviderException, SignatureException
   {
	  // generate the certificate
	  X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	  certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
	  certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
	  certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
	  certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
	  certGen.setPublicKey(pair.getPublic());
	  certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
      return certGen.generateX509Certificate(pair.getPrivate(), "BC");
   }

   public static void X509V1CreateExample() throws Exception
   {
	  // create the keys
	  KeyPair pair = Utils.generateRSAKeyPair();
      // generate the certificate
	  X509Certificate cert = generateV1Certificate(pair);
      // show some basic validation
	  cert.checkValidity(new Date());
      cert.verify(cert.getPublicKey());
      System.out.println("valid certificate generated");
   }

   public static X509Certificate generateV3Certificate(KeyPair pair)
	       throws InvalidKeyException, NoSuchProviderException, SignatureException
   {
	  // generate the certificate
	  X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	  certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
	  certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
	  certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
	  certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
	  certGen.setPublicKey(pair.getPublic());
	  certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
      certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
	  certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
	  certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
      certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
    		  new GeneralName(GeneralName.rfc822Name, "test@test.test")));
      return certGen.generateX509Certificate(pair.getPrivate(), "BC");
   }
   
   public static X509Certificate generateV3Certificate(KeyPair pair, String issuer, String purpose, String email)
   		throws InvalidKeyException, NoSuchProviderException, SignatureException
   {
   	// generate the certificate
   	X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
   	certGen.setIssuerDN(new X500Principal(issuer));
   	certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
   	certGen.setNotAfter(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24 * 365))); // 1 Year
   	certGen.setSubjectDN(new X500Principal(purpose));
   	certGen.setPublicKey(pair.getPublic());
   	certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
       certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
   	certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
   	certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
   	certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, 
       		email)));
       return certGen.generateX509Certificate(pair.getPrivate(), "BC");
   }
   
   public static X509Certificate generateV3CertificateLlavesCargadas(Key kpublic, Key kprivada, String issuer, String purpose, String email)
	   		throws InvalidKeyException, NoSuchProviderException, SignatureException
	   {
	   	// generate the certificate
	   	X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
	    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	   	certGen.setIssuerDN(new X500Principal(issuer));
	   	certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
	   	certGen.setNotAfter(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 365)); // 1 Year
	   	certGen.setSubjectDN(new X500Principal(purpose));
	   	certGen.setPublicKey((PublicKey)kpublic);
	   	certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
	       certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
	   	certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
	   	certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
	   	certGen.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.rfc822Name, 
	       		email)));
	       return certGen.generateX509Certificate((PrivateKey)kprivada, "BC");
	   }
   
   public static void X509V3CreateExample() throws Exception
   {
	  // create the keys
	  KeyPair pair = Utils.generateRSAKeyPair();
      // generate the certificate
	  X509Certificate cert = generateV3Certificate(pair);
      // show some basic validation
	  cert.checkValidity(new Date());
      cert.verify(cert.getPublicKey());
      System.out.println("valid certificate generated");
   }
 
   // Basic example of using a CertificateFactory
   public static void CertificateFactoryExample() throws Exception
   {
      // create the keys
      KeyPair pair = Utils.generateRSAKeyPair();;
      // create the input stream
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      bOut.write(generateV1Certificate(pair).getEncoded());
      bOut.close();
      InputStream in = new ByteArrayInputStream(bOut.toByteArray());
      // create the certificate factory
      CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
      // read the certificate
      X509Certificate x509Cert = (X509Certificate)fact.generateCertificate(in);
      System.out.println("issuer: " + x509Cert.getIssuerX500Principal());
   }

   // Basic example of reading multiple certificates with a CertificateFactory
   public static void MultipleCertificateExample() throws Exception
   {
      // create the keys
      KeyPair pair = Utils.generateRSAKeyPair();
      // create the input stream
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();
      bOut.write(generateV1Certificate(pair).getEncoded());
      bOut.write(generateV3Certificate(pair).getEncoded());
      bOut.close();
      InputStream in = new ByteArrayInputStream(bOut.toByteArray());
      // create the certificate factory
      CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
      // read the certificate
      X509Certificate   x509Cert;
      Collection collection = new ArrayList();
      while((x509Cert = (X509Certificate)fact.generateCertificate(in)) != null)
      {
         collection.add(x509Cert);
      }
      Iterator it = collection.iterator();
      while (it.hasNext())
      {
         System.out.println("version: " + ((X509Certificate)it.next()).getVersion());
      }
   }
   
   // Generation of a basic PKCS #10 request
   public static PKCS10CertificationRequest generateRequest(KeyPair pair) throws Exception
   {
	  // create a SubjectAlternativeName extension value
	  GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@test.test"));
      // create the extensions object and add it as an attribute
	  Vector oids = new Vector();
	  Vector values = new Vector();
      oids.add(X509Extensions.SubjectAlternativeName);
      values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
      X509Extensions extensions = new X509Extensions(oids, values);
      Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
      return new PKCS10CertificationRequest("SHA256withRSA", new X500Principal("CN=Requested Test Certificate"), 
	     pair.getPublic(), new DERSet(attribute), pair.getPrivate());
   }

   public static void PKCS10CertRequestExample() throws Exception
   {
	  // create the keys
	  KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
      kpGen.initialize(1024, Utils.createFixedRandom());
      KeyPair pair = kpGen.generateKeyPair();
      PKCS10CertificationRequest request = generateRequest(pair);
      PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
      pemWrt.writeObject(request);
      pemWrt.close();
   }

   public static void PKCS10ExtensionExample() throws Exception
   {
      // create the keys
      KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
      kpGen.initialize(1024, Utils.createFixedRandom());
      KeyPair pair = kpGen.generateKeyPair();
      PKCS10CertificationRequest request = generateRequest(pair);
      PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
      pemWrt.writeObject(request);
      pemWrt.close();
   }

   // Try It Out: Creating a Certificate from a Certification Request 
   public static X509Certificate[] buildChain() throws Exception
   {
      // create the certification request
      KeyPair pair = Utils.generateRSAKeyPair();
      PKCS10CertificationRequest request = generateRequest(pair);
      // create a root certificate
      KeyPair rootPair = Utils.generateRSAKeyPair();
      X509Certificate rootCert = generateV1Certificate(rootPair);
      // validate the certification request
      if (!request.verify("BC"))
      {
         System.out.println("request failed to verify!");
         System.exit(1);
      }
      // create the certificate using the information in the request
      X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
      certGen.setIssuerDN(rootCert.getSubjectX500Principal());
      certGen.setNotBefore(new Date(System.currentTimeMillis()));
      certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
      certGen.setSubjectDN(request.getCertificationRequestInfo().getSubject());
      certGen.setPublicKey(request.getPublicKey("BC"));
      certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
      certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCert));
      certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, 
    		  new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));
      certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
      certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
      certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
      // extract the extension request attribute
      ASN1Set attributes = request.getCertificationRequestInfo().getAttributes();
      for (int i = 0; i != attributes.size(); i++)
      {
         Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));
         // process extension request
         if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest))
         {
            X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
            Enumeration e = extensions.oids();
            while (e.hasMoreElements())
            {
               DERObjectIdentifier oid = (DERObjectIdentifier)e.nextElement();
               X509Extension ext = extensions.getExtension(oid);
               certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
            }
         }
      }
      X509Certificate issuedCert = certGen.generateX509Certificate(rootPair.getPrivate());
      return new X509Certificate[] { issuedCert, rootCert };
   }
   
   public static void PKCS10CertCreateExample() throws Exception
   {
      X509Certificate[] chain = buildChain();
      PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
      pemWrt.writeObject(chain[0]);
      pemWrt.writeObject(chain[1]);
      pemWrt.close();
   }
   
   // Basic example of creating and encoding a CertPath
   public static void CertPathExample() throws Exception
   {
      X509Certificate[] chain = buildChain();
      // create the factory and path object
      CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
      CertPath certPath = fact.generateCertPath(Arrays.asList(chain));
      byte[] encoded = certPath.getEncoded("PEM");
      System.out.println(Utils.toString(encoded));
      // re-read the CertPath
      CertPath newCertPath = fact.generateCertPath(new ByteArrayInputStream(encoded), "PEM");
      if(newCertPath.equals(certPath))
      {
          System.out.println("CertPath recovered correctly");
      }
   }

   // Example using a CertStore and a CertSelector
   public static void CertStoreExample() throws Exception
   {
	  X509Certificate[] chain = buildChain();
      // create the store
      CollectionCertStoreParameters params = new CollectionCertStoreParameters(Arrays.asList(chain));
      CertStore store = CertStore.getInstance("Collection", params);
      // create the selector
	  X509CertSelector selector = new X509CertSelector();
      selector.setSubject(new X500Principal("CN=Requested Test Certificate").getEncoded());
      // print the subjects of the results
      Iterator certsIt = store.getCertificates(selector).iterator();
	  while (certsIt.hasNext())
      {
		 X509Certificate cert = (X509Certificate)certsIt.next();
		 System.out.println(cert.getSubjectX500Principal());
	  }
   }

   
}
