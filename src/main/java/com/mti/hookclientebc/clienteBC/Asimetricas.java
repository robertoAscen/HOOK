package com.mti.hookclientebc.clienteBC;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;

import Encriptacion.*;

import hookCap8.*;

public class Asimetricas 
{
    private KeyPair 		asimetricas;
    private Key 		privKey;
    private Key 		pubKey;
    private SecureRandom   	random;
	
    public void GeneraRSA2048() throws Exception
    {
	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
	random = new SecureRandom();
	keyGen.initialize(2048, random); 
	asimetricas = keyGen.generateKeyPair();
	privKey = asimetricas.getPrivate();
	pubKey = asimetricas.getPublic();
    }
	
    public void DespliegaPrivada()
    {
    	System.out.println("RSA privada: " + Utils.toHex(privKey.getEncoded()));
    }
    
    public void DespliegaPublica()
    {
    	System.out.println("RSA publica: " + Utils.toHex(pubKey.getEncoded()));
    }
    
    public void DespliegaPublicaOtro(Key pko)
    {
    	System.out.println("RSA publica de otra persona: " + Utils.toHex(pko.getEncoded()));
    }
    
    public void GrabaPrivada(String pass, File f) throws Exception
    {
	KeyStore store = hookCap8.createKeyStorePKCS12(asimetricas);
	char[] password = pass.toCharArray();
	store.store(new FileOutputStream(f), password);
    }
    
    public void GrabaPublica(File f) throws Exception
    {
        FileWriter fw = new FileWriter(f.toString());
        PEMWriter fPEM = new PEMWriter(fw);
        fPEM.writeObject(pubKey);
        fPEM.close();
        fw.close();
    }
    
    public void GeneraAsimetricas() throws Exception
    {
    	GeneraRSA2048();
    }
    
    public void CargaPrivada(String pass, File f) throws Exception
    {
	KeyStore store = KeyStore.getInstance("PKCS12", "BC");
	char[] password = pass.toCharArray();
	store.load(new FileInputStream(f), password);
	privKey = store.getKey("root", password);
    }
    
    public void CargaPublica(File f) throws Exception
    {
	InputStream is = null;
	is = (InputStream)new FileInputStream(f);
	PEMReader r = new PEMReader(new InputStreamReader(is));
	pubKey = (Key)r.readObject();
	r.close();
	is.close();
    }

    public Key CargaPublicaOtro(File f) throws Exception
    {
        InputStream is = null;
        is = (InputStream)new FileInputStream(f);
	PEMReader r = new PEMReader(new InputStreamReader(is));
	Key pubKeyOtro = (Key)r.readObject();
	r.close();
	is.close();
	return pubKeyOtro;
    }
    
    public KeyPair RegresaLlaves() throws Exception
    {
    	return asimetricas;
    }
    
    public Key RegresaPrivada() throws Exception
    {
    	return privKey;
    }
    
    public Key RegresaPublica() throws Exception
    {
    	return pubKey;
    }
    
    public SecureRandom RegresaRandom() throws Exception
    {
    	return random;
    }
}