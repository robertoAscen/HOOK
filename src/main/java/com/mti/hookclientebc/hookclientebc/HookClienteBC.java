package com.mti.hookclientebc.hookclientebc;

import clienteBC.*;
import com.mti.hookclientebc.clienteBC.ClienteBC;
import hookCap1.*;
import hookCap2.*;
import hookCap3.*;
import hookCap4.*;
import hookCap5.*;
import hookCap6.*;
import hookCap7.*;
import hookCap8.*;
import protocolos.*;

import java.security.Security;
import java.util.Date;

import org.bouncycastle.jce.provider.*;

/*
 * @author sergio
 */
public class HookClienteBC 
{
    
    public static void main(String[] args) throws Exception 
    {
        Security.addProvider(new BouncyCastleProvider());
        // Si vas a correr laboratorios del libro de Hook,
        // Debes comentar este try, ya que lo hace de manera indenpendiente
        
        // Si vas a correr ClienteBC hay que dejar este try 
        
        // Quita el candado de 128 bits de la JVM
	try 
        {
            hookCap1.PermiteLlavesGrandes();
	} catch (Exception e1) 
        {
            e1.printStackTrace();
        }
		
        // Capítulo 1 Hook
        //System.out.println("Prueba que se haya eliminado la restricción de 128 bits");
        //hookCap1.SimplePolicyTest();
        //System.out.println("Checa que BC esté instalado");
        //hookCap1.SimpleProviderTest();
        //System.out.println("Prueba la precedencia de proveedores de seguridad");
        //hookCap1.PrecedenceTest();
        //System.out.println("Despliega las capacidades del proveedor Bouncy Castle");
        //hookCap1.ListBCCapabilities();
		
        // Capítulo 2 Hook
        //System.out.println("Encripta con AES y una llave alambrada");
        //hookCap2.SimpleSymmetricExample();
        //System.out.println("Encripta con AES, una llave alambrada, y rellenando con PKCS7Padding");
        //hookCap2.SimpleSymmetricPaddingExample();
        //System.out.println("Encripta con DES, en modo ECB, llave alambrada");
        //System.out.println("Observar que 3260266c2cf202e2 se repite en el criptograma, porque se repite 001020304050607 en la entrada");
        //hookCap2.SimpleECBExample();
        //System.out.println("Encripta con DES, en modo CBC, llave alambrada");
        //hookCap2.SimpleCBCExample();
        //System.out.println("Encripta con DES, en modo CBC, con IV (Initialization Vector), llave alambrada");
        //hookCap2.InlineIvCBCExample();
        //System.out.println("Encripta con DES, en modo CBC, con IV (Initialization Vector), semilla y llave alambrada");
        //hookCap2.NonceIvCBCExample();
        //System.out.println("Encripta con DES, en modo CTR, llave alambrada");
        //hookCap2.SimpleCTRExample();
        //System.out.println("Encripta con ARC4 (basado en RC4) y una llave alambrada");
        //hookCap2.SimpleStreamExample();
        //System.out.println("Encripta con AES, en modo CTR, generando la llave");
        //hookCap2.KeyGeneratorExample();
        // C U I D A D O
        // Provoca una excepción al desplegar System.out.println ("gen key: " + Utils.toHex(sKey.getEncoded()));
        // pad block corrupted
        // Era un código que traía varios errores de sintaxis, en el Hook
        //System.out.println("Encripta con DESede y PBE (Password Based Encryption), llave alambrada");
        //hookCap2.PBEWithParamsExample();
        //System.out.println("Encripta con DESede y PBE (Password Based Encryption) sin usar PBEParameterSpec, llave alambrada");
        //hookCap2.PBEWithoutParamsExample();
        //System.out.println("Envoltura de una llave AES");
        //hookCap2.SimpleWrapExample();
        //System.out.println("Usando Entrada y Salida segura, llave alambrada");
        //hookCap2.SimpleIOExample();
				
        // Capítulo 3 Hook
        //System.out.println("\nHombre en el medio con un criptograma AES y modo CTR");
        //hookCap3.TamperedExample();
        //System.out.println("\nHombre en el medio con un criptograma AES y modo CTR, invalidado por un message digest SHA-1");
        //hookCap3.TamperedWithDigestExample();
        //System.out.println("\nHombre en el medio con un criptograma AES y modo CTR, invalidado por un HMAC SHA-1");
        //System.out.println("\nEn un HMAC, la clave secreta interviene en el hash");
        //hookCap3.TamperedWithHMacExample();
        //System.out.println("\nProtección de la integridad de un criptograma AES y modo CTR, con MAC(DES)");
        //hookCap3.CipherMacExample();
        //System.out.println("\nPBE con DES, en modo CBC, y SHA-1");
        //hookCap3.PKCS5Scheme1Test();
        //System.out.println("\nEnmascarando (ofuscando) un message digest");
        //hookCap3.MaskGeneration();
        //System.out.println("\nIO seguro de un message digest");
        //hookCap3.DigestIOExample();
    	
        // Capítulo 4 Hook
        //System.out.println("Encripta con RSA el hexadecimal beef con una clave pública de 256 bits y una privada de 128 bits");
        //hookCap4.BaseRSAExample();
        //System.out.println("\nEncripta con RSA el hexadecimal beef generando de manera aleatoria dos claves (privada y pública)");
        //hookCap4.RandomKeyRSAExample();
        //System.out.println("\nEncripta con RSA el hexadecimal 00beef usando Padding PKCS 1.5");
        //hookCap4.PKCS1PaddedRSAExample();
        //System.out.println("\nEncripta con RSA el hexadecimal 00beef usando OAEP Padding");
        //hookCap4.OAEPPaddedRSAExample();
        //System.out.println("\nWrapping RSA Keys");
        //hookCap4.AESWrapRSAExample(); 
        //System.out.println("\nSecret Key Exchange");
        //hookCap4.RSAKeyExchangeExample();
        //System.out.println("\nDiffie-Hellman Key Agreement");
        //System.out.println("Alice y Bob tienen la misma llave pública, calculada gracias al problema del logaritmo discreto y curvas elípticas");
        //System.out.println("Además, escala bien (por lo menos a tres participantes)");
        //hookCap4.BasicDHExample();
        //System.out.println("\nDiffie-Hellman with Elliptic Curve");
        //hookCap4.BasicECDHExample();
        //System.out.println("\nDiffie-Hellman Three-Party Key Agreement");
        //hookCap4.BasicThreePartyDHExample();
        //System.out.println("\nEl Gamal example with random key generation");
        //hookCap4.RandomKeyElGamalExample();
        //System.out.println("\nEl Gamal Using AlgorithmParameterGenerator");
        //hookCap4.AlgorithmParameterExample();
        //System.out.println("\nDSA Digital Signature Algorithm");
        //hookCap4.BasicDSAExample();
        //System.out.println("DSA with Elliptic Curve");
        //System.out.println("Simple example showing signature creation and verification using ECDSA");
        //hookCap4.BasicECDSAExample();
        //System.out.println("RSA Signature Generation");
        //hookCap4.PKCS1SignatureExample();
	
        // Capitulo 5 Hook
        //System.out.println("Prueba de MyStructure");
        //hookCap5.MyStructureTest();
        //System.out.println("Example for ASN1Dump using MyStructure");
        //hookCap5.ASN1DumpExample();
        //System.out.println("Example showing IV encoding");
        //hookCap5.IVExample();
        //System.out.println("Basic class for exploring PKCS #1 V1.5 Signatures");
        //hookCap5.PKCS1SigEncodingExample();
        //System.out.println("Example showing PSS (Probabilistic Signature Scheme (RSA)) parameter recovery and encoding");
        //hookCap5.PSSParamExample();
        //System.out.println("Genera un par de llaves RSA, envuelve la llave pública en un wrap y luego recupera la llave pública del sobre y la despliega");
        //hookCap5.X509EncodedKeySpecExample();
        //System.out.println("Simple example showing how to use PBE and an EncryptedPrivateKeyInfo object");
        //System.out.println("Genera una llave privada, la encripta con TripleDes y PBE, la ensobreta, la desensobreta y desencripta");
        //System.out.println("You have a collection of INTEGER objects representing a regular RSA private key that uses Chinese Remainder Theorem and an optional extra field for a sequence of extra values on the end in case the key is a multi-prime one");
        //hookCap5.EncryptedPrivateKeyInfoExample();
		
        // Capítulo 6 Hook
        //System.out.println("\nCreating a Self-Signed Version 1 Certificate");
        //hookCap6.X509V1CreateExample();
        //System.out.println("\nCreating a Self-Signed Version 3 Certificate");
        //hookCap6.X509V3CreateExample();
        //System.out.println("\nBasic example of using a CertificateFactory");
        //hookCap6.CertificateFactoryExample();
        //System.out.println("\nReading Multiple Certificates ");
        //hookCap6.MultipleCertificateExample();
        //System.out.println("\nCreating a Certification Request");
        //hookCap6.PKCS10CertRequestExample();
        //System.out.println("\nGeneration of a basic PKCS #10 request with an extension");
        //hookCap6.PKCS10ExtensionExample();
        //System.out.println("\nAn example of a basic CA");
        //hookCap6.PKCS10CertCreateExample();
        //System.out.println("\nWriting a CertPath");
        //hookCap6.CertPathExample();
        //System.out.println("\nUsing a CertStore and a CertSelector");
        //hookCap6.CertStoreExample();

        // Capítulo 7 Hook
        //System.out.println("\nBasic Example of generating and using a CRL Certification Revocation List");
        //hookCap7.X509CRLExample();
        //System.out.println("\nReading a CRL with a CertificateFactory");
        //hookCap7.CRLCertFactoryExample();
        //System.out.println("\nUsing the X509CRLSelector and the CertStore classes");
        //hookCap7.CRLCertStoreExample();
        //System.out.println("\nExample of unsigned OCSP request generation");
        //hookCap7.OCSPClientExample();
        //System.out.println("\nExample of OCSP response generation");
        //hookCap7.OCSPResponderExample();
        //System.out.println("\nBasic example of certificate path validation");
        //hookCap7.CertPathValidatorExample();
        //System.out.println("\nBasic example of certificate path validation using a PKIXCertPathChecker");
        //hookCap7.CertPathValidatorWithCheckerExample();
        //System.out.println("\nBasic example of the use of CertPathBuilder");
        //hookCap7.CertPathBuilderExample();
		
        // Capítulo 8 Hook
        //System.out.println("\nExample of basic use of KeyStore");
        //hookCap8.JKSStoreExample();
        //System.out.println("\nExample of using a JCEKS keystore with KeyStore.Entry and KeyStore.ProtectionParameter objects");
        //hookCap8.JCEKSStoreEntryExample();
        //System.out.println("\nBasic example of use of KeyStore.Builder to create an object that can be used recover a private key");
        //HookCap8.JCEKSStoreBuilderExample();
        //System.out.println("\nUsing a PKCS #12 Keystore");
        //hookCap8.PKCS12StoreExample();
        //System.out.println("\nCreate some keystore files in the current directory");
        //hookCap8.KeyStoreFileUtility();
		
        // Protocolos
        //System.out.println("\nProtocolo de Confidencialidad con RSA");
        //Protocolos.ProtocoloConfidencialidadRSA();
        //System.out.println("\nProtocolo de Autenticación con RSA");
        //Protocolos.ProtocoloAutenticacionRSA();
        //System.out.println("\nProtocolo de Confidencialidad, Autenticación e Integridad con RSA y Hash");
        //Protocolos.ProtocoloConfidencencialidadAutenticacionIntegridadRSAHash();
        //System.out.println("\nProtocolo de Confidencialidad y Autenticación con AES");
        //Protocolos.ProtocoloConfidencialidadAutenticacionAES();
        //System.out.println("\nProtocolo de Confidencialidad y Autenticación con Triple Des");
        //Protocolos.ProtocoloConfidencialidadAutenticacionTripleDes();
        //System.out.println("\nProtocolo de Confidencialidad y Autenticación con Des");
        //Protocolos.ProtocoloConfidencialidadAutenticacionDes();
        //System.out.println("\nProtocolo de Confidencialidad y Autenticación con Blowfish");
        //Protocolos.ProtocoloConfidencialidadAutenticacionBlowfish();

        // ClienteBC
        // Genera toda la práctica
        ClienteBC AliceBC = new ClienteBC();
        ClienteBC BobBC = new ClienteBC();
        AliceBC.AliceBCPruebaPaso1();
        BobBC.BobBCPruebaPaso2();
        AliceBC.AliceBCPruebaPaso3();
        BobBC.BobBCPruebaPaso4();	
        AliceBC.AliceBCPruebaPaso5(); 
    }
}