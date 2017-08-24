package clienteBC;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Encriptacion.Utils;

public class Mensaje 
{
    public byte[] EncriptaMensajeAES(String Mensaje, Key simetricKey) throws Exception
    {
	byte[] ByteMensaje = Utils.toByteArray(Mensaje);
	byte[] ivBytes = new byte[] { 
            0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
	cipher.init(Cipher.ENCRYPT_MODE, simetricKey, new IvParameterSpec(ivBytes));
	byte[] cipherText = new byte[cipher.getOutputSize(ByteMensaje.length)];
	int ctLength = cipher.update(ByteMensaje, 0, ByteMensaje.length, cipherText, 0);
	ctLength += cipher.doFinal(cipherText, ctLength);
	return cipherText;
    }
    
    public String DesencriptaMensajeAES(byte[] MensajeEncriptado, Key simetricKey) throws Exception
    {
	byte[] ivBytes = new byte[] { 
            0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    	Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
    	Key decryptionKey = new SecretKeySpec(simetricKey.getEncoded(), simetricKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
    	byte[] plainText = new byte[cipher.getOutputSize(MensajeEncriptado.length)];
    	int ptLength = cipher.update(MensajeEncriptado, 0, MensajeEncriptado.length, plainText, 0);
	ptLength += cipher.doFinal(plainText, ptLength);
	return new String(plainText);
    }
	
    public void DespliegaMensaje(String Mensaje)
    {
    	System.out.println("Mensaje en texto plano: " + Mensaje);
    }
    
    public void DespliegaMensajeEncriptado(byte[] MensajeEncriptado)
    {
    	System.out.println("Mensaje encriptado: " + Utils.toHex(MensajeEncriptado));    	
    }
    
    public void GrabaMensajeEncriptado(byte[] MensajeEncriptado, File f) throws Exception
    {
	FileOutputStream fos = new FileOutputStream(f);
	fos.write(MensajeEncriptado);
	fos.close();
    }
    
    public byte[] CargaMensajeEncriptado(File f) throws Exception
    {
        byte[] MensajeEncriptado = new byte[(int)f.length()];
     	FileInputStream fis = new FileInputStream(f);
     	fis.read(MensajeEncriptado, 0, MensajeEncriptado.length);
     	fis.close();
    	return MensajeEncriptado;
    }
    
    public byte[] CargaMensajeEncriptadoFileReader(FileReader f) throws Exception
    {
        BufferedReader buffReader = new BufferedReader(f);
        //Aqui guardaremos cada linea del archivo por vez
        String linea=null;
        //Aqui acumularemos todas las lineas
        String contenido="";
        //Cada que se invoca el metodo readLine() se busca una linea y el cursor
        //pasa a la siguiente linea cuando no hay mas lineas regresa null
        while((linea=buffReader.readLine())!=null){
           System.out.println(linea);
           contenido+=" "+linea;
        }
        //Se valida que no sea nulo y se cierra
        if( null != f)
              f.close();
        return Utils.toByteArray(contenido);
    }
    
    public byte[] EncriptaLlaveAESConRSA(Key pub, Key sk) throws Exception
    {
	Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] cipherText = cipher.doFinal(sk.getEncoded());
        return cipherText;
    }
    
    public Key DesencriptaLlaveAESConRSA(Key pk, byte[] criptogramaAES) throws Exception
    {
    	Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
    	cipher.init(Cipher.DECRYPT_MODE, pk);
    	byte[] plainAES = cipher.doFinal(criptogramaAES);
    	System.out.println("plainAES:  " + Utils.toHex(plainAES));  
    	SecretKey decryptionKey = new SecretKeySpec(plainAES, "AES");
    	return decryptionKey;
    }
    
    public byte[] EncriptaMensajeRSA(Key pub, byte[] Mensaje, SecureRandom rand) throws Exception
    {
	Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pub, rand);
        byte[] cipherText = cipher.doFinal(Mensaje);
        return cipherText;
    }
    
    public byte[] DesEncriptaMensajeRSA(Key pk, byte[] criptograma) throws Exception
    {
    	Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
    	cipher.init(Cipher.DECRYPT_MODE, pk);
    	byte[] plain = cipher.doFinal(criptograma);
    	System.out.println("plain:  " + plain.toString());  
    	return plain;
    }
}