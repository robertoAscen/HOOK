package com.mti.hookclientebc.clienteBC;

import hookCap6.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;

import base64.Base64Encoder;

public class Certificado {

    public X509Certificate cert;
	
    public void GeneraCertificado(KeyPair asimetricas, String issuer, String purpose, String email) throws Exception
    {
	cert = hookCap6.generateV3Certificate(asimetricas, issuer, purpose, email);
	cert.checkValidity(new Date());
	cert.verify(cert.getPublicKey());
    }
	
    public void GeneraCertificadoLlavesCargadas(Key kpublica, Key kprivada, String issuer, String purpose, String email) throws Exception
    {
	cert = hookCap6.generateV3CertificateLlavesCargadas(kpublica, kprivada, issuer, purpose, email);
	cert.checkValidity(new Date());
	cert.verify(cert.getPublicKey());
    }
    
    public void ValidaCertificado() throws Exception
    {
	cert.checkValidity(new Date());
	cert.verify(cert.getPublicKey());
    }
	
    public void GrabaCertificado(File f) throws Exception
    {
	FileWriter file_cert = new FileWriter(f);
	PEMWriter pemWriter_cert = new PEMWriter(file_cert);
	pemWriter_cert.writeObject(cert);
	pemWriter_cert.close();
	file_cert.close();
    }
    
    public void DespliegaCertificado() throws Exception
    {
	Base64Encoder b64 = new Base64Encoder();
	System.out.println("-----BEGIN CERTIFICATE-----");
	System.out.println("Certificate: " + b64.encode(cert.getEncoded()));
	System.out.println("-----END CERTIFICATE-----"); 
    }
    
    public void CargaCertificado(File f) throws Exception 
    {
	InputStream is = null;
	is = (InputStream)new FileInputStream(f);
	PEMReader r = new PEMReader(new InputStreamReader(is));
	cert = (X509Certificate) r.readObject();
	r.close();
	is.close();
    }
    
    public X509Certificate RegresaCertificado() throws Exception
    {
	return cert;
    }
}
