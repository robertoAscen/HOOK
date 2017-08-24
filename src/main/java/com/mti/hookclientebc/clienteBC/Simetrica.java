package com.mti.hookclientebc.clienteBC;

import static org.apache.commons.codec.binary.Hex.decodeHex;
import static org.apache.commons.codec.binary.Hex.encodeHex;
import static org.apache.commons.io.FileUtils.readFileToByteArray;
import static org.apache.commons.io.FileUtils.writeStringToFile;

import java.io.File;
import java.io.IOException;
import java.security.Key;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;

import Encriptacion.Utils;

public class Simetrica 
{
    public Key 	simetricKey;
	
    public Key GeneraAES256() throws Exception
    {
    	KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
    	Key encryptionSimetricKey;
       	generator.init(256); // 128 default; 192 y 256 son permitidos
        encryptionSimetricKey = generator.generateKey();  
        return encryptionSimetricKey;
    }
    
    public void DespliegaSimetrica()
    {
	System.out.println("Key AES: " + Utils.toHex(simetricKey.getEncoded()));
    }
    
    public void GeneraSimetrica() throws Exception
    {
    	simetricKey = GeneraAES256();
    }
    
    public Key RegresaSimetrica() throws Exception
    {
    	return simetricKey;
    }
    
    public void FijaSimetrica(Key sk) throws Exception
    {
    	simetricKey = sk;
    }
} 