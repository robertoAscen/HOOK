package hookCap7;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.*;

public class X509CRLExample 
{
   public static X509CRL createCRL(X509Certificate caCert, PrivateKey caKey, BigInteger revokedSerialNumber) throws Exception
   {
	  X509V2CRLGenerator  crlGen = new X509V2CRLGenerator();
	  Date                now = new Date();
	  crlGen.setIssuerDN(caCert.getSubjectX500Principal());
	  crlGen.setThisUpdate(now);
	  crlGen.setNextUpdate(new Date(now.getTime() + 100000));
	  crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
	  crlGen.addCRLEntry(revokedSerialNumber, now, CRLReason.privilegeWithdrawn);
	  crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
	  crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
	  return crlGen.generateX509CRL(caKey, "BC");
   }
}
