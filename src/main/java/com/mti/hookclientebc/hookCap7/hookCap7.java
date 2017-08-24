package hookCap7;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.util.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.*;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.Req;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.*;

import Encriptacion.Utils;

public class hookCap7 
{   
	/**
	 * Basic Example of generating and using a CRL.
	 */
   // Fue revocado por el cambio de 
   // crlGen.setIssuerDN(issuedCert.getIssuerX500Principal());
   // a
   // crlGen.setIssuerDN(caCert.getSubjectX500Principal());
   public static void X509CRLExample() throws Exception
   {
      // create CA keys and certificate
      KeyPair         caPair = Utils.generateRSAKeyPair();
      X509Certificate caCert = Utils.generateRootCert(caPair);
      BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
      // create a CRL revoking certificate number 2
      X509CRL crl = X509CRLExample.createCRL(caCert, caPair.getPrivate(), revokedSerialNumber);
      // verify the CRL
      crl.verify(caCert.getPublicKey(), "BC");
      // check if the CRL revokes certificate number 2
      X509CRLEntry entry = crl.getRevokedCertificate(revokedSerialNumber);
      System.out.println("Revocation Details:");
      System.out.println(" Certificate number: " + entry.getSerialNumber());
      System.out.println(" Issuer            : " +crl.getIssuerX500Principal());
      if (entry.hasExtensions())
      {
         byte[] ext = entry.getExtensionValue(X509Extensions.ReasonCode.getId());
         if (ext != null)
         {
             DEREnumerated reasonCode = (DEREnumerated)X509ExtensionUtil.fromExtensionValue(ext);
             System.out.println("    Reason Code      : "+reasonCode.getValue());
         }
      }
   }
   
   // Reading a CRL with a CertificateFactory
   public static void CRLCertFactoryExample() throws Exception
   {
      // create CA keys and certificate
      KeyPair         caPair = Utils.generateRSAKeyPair();
      X509Certificate caCert = Utils.generateRootCert(caPair);
      BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
      // create a CRL revoking certificate number 2
      X509CRL crl = X509CRLExample.createCRL(caCert, caPair.getPrivate(), revokedSerialNumber);
      // encode it and reconstruct it
      ByteArrayInputStream bIn = new ByteArrayInputStream(crl.getEncoded());
      CertificateFactory   fact = CertificateFactory.getInstance("X.509", "BC");
      crl = (X509CRL)fact.generateCRL(bIn);
      // verify the CRL
      crl.verify(caCert.getPublicKey(), "BC");
      // check if the CRL revokes certificate number 2
      X509CRLEntry entry = crl.getRevokedCertificate(revokedSerialNumber);
      System.out.println("Revocation Details:");
      System.out.println(" Certificate number: " + entry.getSerialNumber());
      System.out.println(" Issuer            : " +crl.getIssuerX500Principal());
   }
   
   // Using the X509CRLSelector and the CertStore classes
   public static void CRLCertStoreExample() throws Exception
   {
	  // create CA keys and certificate
	  KeyPair          caPair = Utils.generateRSAKeyPair();
	  X509Certificate  caCert = Utils.generateRootCert(caPair);
	  BigInteger       revokedSerialNumber = BigInteger.valueOf(2);
      // create a CRL revoking certificate number 2
      X509CRL crl = X509CRLExample.createCRL(caCert, caPair.getPrivate(), revokedSerialNumber);
      // place the CRL into a CertStore
	  CollectionCertStoreParameters params = new CollectionCertStoreParameters(Collections.singleton(crl));
	  CertStore store = CertStore.getInstance("Collection", params, "BC");
	  X509CRLSelector selector = new X509CRLSelector();
      selector.addIssuerName(caCert.getSubjectX500Principal().getEncoded());
      Iterator it = store.getCRLs(selector).iterator();
      while (it.hasNext())
      {
         crl = (X509CRL)it.next();
         // verify the CRL
		 crl.verify(caCert.getPublicKey(), "BC");
         // check if the CRL revokes certificate number 2
         X509CRLEntry entry = crl.getRevokedCertificate(revokedSerialNumber);
         System.out.println("Revocation Details:");
         System.out.println(" Certificate number: " + entry.getSerialNumber());
         System.out.println(" Issuer            : " + crl.getIssuerX500Principal());
	  }
   }
   
   public static OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws OCSPException
   {
	  // Generate the id for the certificate we are looking for
	  CertificateID id = new CertificateID(CertificateID.HASH_SHA1, issuerCert, serialNumber);
      // basic request generation with nonce
      OCSPReqGenerator gen = new OCSPReqGenerator();
      gen.addRequest(id);
      // create details for nonce extension
      BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
      Vector     oids = new Vector();
      Vector     values = new Vector();
      oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
      gen.setRequestExtensions(new X509Extensions(oids, values));
      return gen.generate();
   }

   // Example of unsigned OCSP request generation
   public static void OCSPClientExample() throws Exception
   {
	  // create certificates and CRLs
	  KeyPair rootPair = Utils.generateRSAKeyPair();
	  KeyPair interPair = Utils.generateRSAKeyPair();
      X509Certificate rootCert = Utils.generateRootCert(rootPair);
      X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
      OCSPReq request = generateOCSPRequest(rootCert, interCert.getSerialNumber());
      Req[] requests = request.getRequestList();
      for (int i = 0; i != requests.length; i++)
      {
         CertificateID certID = requests[i].getCertID();
         System.out.println("OCSP Request to check certificate number " + certID.getSerialNumber());
	  }
   }

   // Example of OCSP response generation
   public static void OCSPResponderExample() throws Exception
   {
	  KeyPair        rootPair = Utils.generateRSAKeyPair();
	  KeyPair        interPair = Utils.generateRSAKeyPair();
      X509Certificate rootCert = Utils.generateRootCert(rootPair);
	  X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
      System.out.println(OCSPResponderExample.getStatusMessage(rootPair, rootCert, BigInteger.valueOf(2), interCert));
   }
   
   // Basic example of certificate path validation
   public static void CertPathValidatorExample() throws Exception
   {
      // create certificates and CRLs
      KeyPair         rootPair = Utils.generateRSAKeyPair();
      KeyPair         interPair = Utils.generateRSAKeyPair();
      KeyPair         endPair = Utils.generateRSAKeyPair();
      X509Certificate rootCert = Utils.generateRootCert(rootPair);
      X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
      X509Certificate endCert = Utils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
      BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
      X509CRL  rootCRL = X509CRLExample.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
      X509CRL  interCRL = X509CRLExample.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);
      // create CertStore to support validation
      List list = new ArrayList();
      list.add(rootCert);
      list.add(interCert);
      list.add(endCert);
      list.add(rootCRL);
      list.add(interCRL);
      CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
      CertStore store = CertStore.getInstance("Collection", params, "BC");
      // create certificate path
      CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
      List               certChain = new ArrayList();
      certChain.add(endCert);
      certChain.add(interCert);
      CertPath certPath = fact.generateCertPath(certChain);
      Set      trust = Collections.singleton(new TrustAnchor(rootCert, null));
      // perform validation
      CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
      PKIXParameters param = new PKIXParameters(trust);
      param.addCertStore(store);
      param.setDate(new Date());
      try
      {
          CertPathValidatorResult result = validator.validate(certPath, param);
          System.out.println("certificate path validated");
      }
      catch (CertPathValidatorException e)
      {
          System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
      }
   }
   
   // Basic example of certificate path validation using a PKIXCertPathChecker
   public static void CertPathValidatorWithCheckerExample() throws Exception
   {
      // create certificates and CRLs
      KeyPair         rootPair = Utils.generateRSAKeyPair();
      KeyPair         interPair = Utils.generateRSAKeyPair();
      KeyPair         endPair = Utils.generateRSAKeyPair();
      X509Certificate rootCert = Utils.generateRootCert(rootPair);
      X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
      X509Certificate endCert = Utils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
      BigInteger revokedSerialNumber = BigInteger.valueOf(2);
      // create CertStore to support validation
      List list = new ArrayList();
      list.add(rootCert);
      list.add(interCert);
      list.add(endCert);
      CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
      CertStore store = CertStore.getInstance("Collection", params, "BC");
      // create certificate path
      CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
      List certChain = new ArrayList();
      certChain.add(endCert);
      certChain.add(interCert);
      CertPath certPath = fact.generateCertPath(certChain);
      Set trust = Collections.singleton(new TrustAnchor(rootCert, null));
      // perform validation
      CertPathValidator validator = CertPathValidator.getInstance("PKIX", "BC");
      PKIXParameters param = new PKIXParameters(trust);
      param.addCertPathChecker(new PathChecker(rootPair, rootCert, revokedSerialNumber));
      param.setRevocationEnabled(false);
      param.addCertStore(store);
      param.setDate(new Date());
      try
      {
         CertPathValidatorResult result = validator.validate(certPath, param);
         System.out.println("certificate path validated");
      }
      catch (CertPathValidatorException e)
      {
         System.out.println("validation failed on certificate number " + e.getIndex() + ", details: " + e.getMessage());
      }
   }
   
   // Basic example of the use of CertPathBuilder
   public static void CertPathBuilderExample() throws Exception
   {
       // create certificates and CRLs
       KeyPair        rootPair = Utils.generateRSAKeyPair();
       KeyPair        interPair = Utils.generateRSAKeyPair();
       KeyPair        endPair = Utils.generateRSAKeyPair();
       X509Certificate rootCert = Utils.generateRootCert(rootPair);
       X509Certificate interCert = Utils.generateIntermediateCert(interPair.getPublic(), rootPair.getPrivate(), rootCert);
       X509Certificate endCert = Utils.generateEndEntityCert(endPair.getPublic(), interPair.getPrivate(), interCert);
       BigInteger      revokedSerialNumber = BigInteger.valueOf(2);
       X509CRL         rootCRL = X509CRLExample.createCRL(rootCert, rootPair.getPrivate(), revokedSerialNumber);
       X509CRL         interCRL = X509CRLExample.createCRL(interCert, interPair.getPrivate(), revokedSerialNumber);
       // create CertStore to support path building
       List list = new ArrayList();
       list.add(rootCert);
       list.add(interCert);
       list.add(endCert);
       list.add(rootCRL);
       list.add(interCRL);
       CollectionCertStoreParameters params = new CollectionCertStoreParameters(list);
       CertStore store = CertStore.getInstance("Collection", params, "BC");
       // build the path
       CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
       X509CertSelector endConstraints = new X509CertSelector();
       endConstraints.setSerialNumber(endCert.getSerialNumber());
       endConstraints.setIssuer(endCert.getIssuerX500Principal().getEncoded());
       PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);
       buildParams.addCertStore(store);
       buildParams.setDate(new Date());
       PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult)builder.build(buildParams);
       CertPath path = result.getCertPath();
       Iterator it = path.getCertificates().iterator();
       while (it.hasNext())
       {
          System.out.println(((X509Certificate)it.next()).getSubjectX500Principal());
       }
       System.out.println(result.getTrustAnchor().getTrustedCert().getSubjectX500Principal());
   }
}