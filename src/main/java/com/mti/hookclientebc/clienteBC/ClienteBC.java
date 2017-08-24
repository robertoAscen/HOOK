package com.mti.hookclientebc.clienteBC;

import java.io.File;
import java.io.FileReader;
import java.security.Key;

import Encriptacion.Utils;
import com.mti.hookclientebc.clienteBC.Asimetricas;
import com.mti.hookclientebc.clienteBC.Certificado;
import clienteBC.Mensaje;
import com.mti.hookclientebc.clienteBC.Simetrica;

public class ClienteBC 
{
    public Asimetricas 		As;
    public Simetrica 		Sim;
    public Mensaje 		Men;
    public Certificado 		Cer;
	
    public Key 			pubKeyOtro;
    public Certificado 		CerOtro;
    public Simetrica		SimOtro;
	
    public ClienteBC() throws Exception
    {
    	As = new Asimetricas();
    	Sim = new Simetrica();
    	Men = new Mensaje();
    	Cer = new Certificado();
    	
    	CerOtro = new Certificado();
    }
	    
    public void AliceBCPruebaPaso1() throws Exception
    {
    	System.out.println("PASO 1");
    	System.out.println("Alice genera y graba llaves asimetricas publica y privada, RSA, de 2048 bits");
    	System.out.println("Alice genera y graba una llave simetrica, AES, de 256 bits, para uso personal");
    	System.out.println("Alice genera y graba un criptograma AES, para Bob");
    	System.out.println("Alice genera y firma un certificado digital");
    	As.GeneraAsimetricas();
    	As.DespliegaPrivada();
    	File pr = new File("Alice_PrivKeystore.p12");
    	As.GrabaPrivada("storePassword",pr);
    	As.CargaPrivada("storePassword",pr);
    	As.DespliegaPrivada();  
    	As.DespliegaPublica();
    	File pu = new File("Alice_Public_RSA.key");
    	As.GrabaPublica(pu);
    	As.CargaPublica(pu);
    	As.DespliegaPublica();
    	Sim.GeneraSimetrica();
    	Sim.DespliegaSimetrica();
        byte[] LlaveAESEncriptada = Men.EncriptaLlaveAESConRSA(As.RegresaPublica(),Sim.RegresaSimetrica());
    	Men.DespliegaMensajeEncriptado(LlaveAESEncriptada);
    	File cr = new File("AES_Alice.crypt");
        Men.GrabaMensajeEncriptado(LlaveAESEncriptada,cr);
        byte[] LlaveAESEncriptada2 = Men.CargaMensajeEncriptado(cr);
        Men.DespliegaMensajeEncriptado(LlaveAESEncriptada2);
    	Sim.FijaSimetrica(Men.DesencriptaLlaveAESConRSA(As.RegresaPrivada(), LlaveAESEncriptada2));
    	System.out.println("La siguiente es una llave AES generada y desencriptada por Alice");
    	Sim.DespliegaSimetrica();
        Cer.GeneraCertificado(As.RegresaLlaves(),
    	    "CN=SERGIO ELLERBRACKE, L=GUADALAJARA, ST=JALISCO, O=UNIVA, C=MEXICO",
            "CN=Test Certificate","sellerbracke@yahoo.com.mx");
    	File fc = new File("Alice_Certificate.cert");
    	Cer.DespliegaCertificado();
    	Cer.GrabaCertificado(fc);
    	Cer.CargaCertificado(fc);
    	Cer.DespliegaCertificado();
    	System.out.println("Alice le envia el certificado digital y la llave publica a Bob");
    }
    
    public void BobBCPruebaPaso2() throws Exception
    {
    	System.out.println("PASO 2");
    	System.out.println("Bob genera llaves asimetricas publica y privada, RSA, de 2048 bits, y graba la publica");
    	System.out.println("Bob recibe el certificado digital y la llave pública de Alice");
    	System.out.println("Bob genera y firma un certificado digital");
    	As.GeneraAsimetricas();
    	As.DespliegaPrivada();
      	As.DespliegaPublica();
    	File pu = new File("Bob_Public_RSA.key");
    	As.GrabaPublica(pu);
    	As.CargaPublica(pu);
    	As.DespliegaPublica();
        Cer.GeneraCertificado(As.RegresaLlaves(),
    	    "CN=Bob, L=GUADALAJARA, ST=JALISCO, O=UNIVA, C=MEXICO",
	    "CN=Test Certificate","bob@yahoo.com.mx");
    	File fc = new File("Bob_Certificate.cert");
    	Cer.DespliegaCertificado();
    	Cer.GrabaCertificado(fc);
    	Cer.CargaCertificado(fc);
    	Cer.DespliegaCertificado();
        System.out.println("Bob le envia el certificado digital y la llave publica a Alice");
    }
    
    public void AliceBCPruebaPaso3() throws Exception
    {
    	System.out.println("PASO 3");
    	System.out.println("Alice recibe el certificado digital y la llave publica de Bob");
    	System.out.println("Alice lee la llave publica de Bob y la valida con el certificado digital de Bob");
    	System.out.println("Alice encripta su llave AES con la llave publica de Bob");
        File pu = new File("Bob_Public_RSA.key");
    	pubKeyOtro = As.CargaPublicaOtro(pu);
    	As.DespliegaPublicaOtro(pubKeyOtro);
    	File fc = new File("Bob_Certificate.cert");
    	CerOtro.CargaCertificado(fc);
    	CerOtro.DespliegaCertificado();
    	CerOtro.ValidaCertificado();
        byte[] LlaveAESParaBobEncriptada = Men.EncriptaLlaveAESConRSA(pubKeyOtro,Sim.RegresaSimetrica());
    	Men.DespliegaMensajeEncriptado(LlaveAESParaBobEncriptada);
    	File cr = new File("AES_Alice_Para_Bob.crypt");
    	Men.GrabaMensajeEncriptado(LlaveAESParaBobEncriptada,cr);
       	byte[] LlaveAESEncriptadaParaBob = Men.CargaMensajeEncriptado(cr);
    	Men.DespliegaMensajeEncriptado(LlaveAESEncriptadaParaBob);
        String Mensaje = "Este es el mensaje que Alice va a enviar a Bob";
    	Men.DespliegaMensaje(Mensaje);
    	byte[] MensajeEncriptado = Men.EncriptaMensajeAES(Mensaje,Sim.RegresaSimetrica());
    	Men.DespliegaMensajeEncriptado(MensajeEncriptado);
    	String MensajePlano = Men.DesencriptaMensajeAES(MensajeEncriptado,Sim.RegresaSimetrica());
    	Men.DespliegaMensaje(MensajePlano);
    	File cr2 = new File("Alice_Message.crypt");
    	Men.GrabaMensajeEncriptado(MensajeEncriptado,cr2);
    	byte[] MensajeEnc = Men.CargaMensajeEncriptado(cr2);
    	Men.DespliegaMensajeEncriptado(MensajeEnc);
    	MensajePlano = Men.DesencriptaMensajeAES(MensajeEnc,Sim.RegresaSimetrica());
    	Men.DespliegaMensaje(MensajePlano);
    }
    
    public void BobBCPruebaPaso4() throws Exception
    {
    	System.out.println("PASO 4");
    	System.out.println("Bob recibe el certificado digital y la llave publica de Alice");
    	System.out.println("Bob lee la llave publica de Alice y la valida con el certificado digital de Alice");
    	System.out.println("Bob desencripta la llave AES de Alice con su llave privada");
    	System.out.println("Bob desencripta el mensaje de Alice");
    	File pu = new File("Alice_Public_RSA.key");
    	pubKeyOtro = As.CargaPublicaOtro(pu);
    	As.DespliegaPublicaOtro(pubKeyOtro);
    	File fc = new File("Alice_Certificate.cert");
    	CerOtro.CargaCertificado(fc);
    	CerOtro.DespliegaCertificado();
    	CerOtro.ValidaCertificado();
    	File dr = new File("AES_Alice_Para_Bob.crypt");
    	byte[] LlaveAESAliceEncriptada = Men.CargaMensajeEncriptado(dr);
    	Men.DespliegaMensajeEncriptado(LlaveAESAliceEncriptada);
    	Sim.FijaSimetrica(Men.DesencriptaLlaveAESConRSA(As.RegresaPrivada(), LlaveAESAliceEncriptada));
    	System.out.println("La siguiente es una llave AES generada por Alice y desencriptada por Bob");
    	Sim.DespliegaSimetrica();
    	File am = new File("Alice_Message.crypt");
    	byte[] MensajeEncriptado = Men.CargaMensajeEncriptado(am);
    	Men.DespliegaMensajeEncriptado(MensajeEncriptado);
    	String MensajePlano = Men.DesencriptaMensajeAES(MensajeEncriptado, Sim.RegresaSimetrica());
    	System.out.println("El siguiente es el mensaje desencriptado que Alice le envio a Bob");
    	Men.DespliegaMensaje(MensajePlano);
        String Mensaje = "La paranoia es aliada de la NSA. Paraliza. Otra tecnica consiste en impedir que alguien pueda comunicarse. A tal fin, la agencia bombardea el telefono con mensajes de texto, acribilla el telefono con llamadas, elimina la presencia online o bloquea el fax. Impedir que funcione el ordenador de alguien. Enviarle un virus. AMBASSADORS RECEPTION: se encripta a si mismo, borra todos los e-mails, encripta todos los archivos, provoca el temblor de la imagen de pantalla, impide entrar en el sistema. Greenwald pp237-238";
    	Men.DespliegaMensaje(Mensaje);
    	byte[] MensajeEncriptado2 = Men.EncriptaMensajeAES(Mensaje,Sim.RegresaSimetrica());
    	Men.DespliegaMensajeEncriptado(MensajeEncriptado2);
    	String MensajePlano2 = Men.DesencriptaMensajeAES(MensajeEncriptado2, Sim.RegresaSimetrica());
    	Men.DespliegaMensaje(MensajePlano2);
    	File cr = new File("Bob_Message.crypt");
    	Men.GrabaMensajeEncriptado(MensajeEncriptado2,cr);
    	byte[] MensajeEnc = Men.CargaMensajeEncriptado(cr);
    	Men.DespliegaMensajeEncriptado(MensajeEnc);
    }
    
    public void AliceBCPruebaPaso5() throws Exception
    {
    	System.out.println("PASO 5");
    	System.out.println("Alice desencripta el mensaje de Bob");
    	File am = new File("Bob_Message.crypt");
    	byte[] MensajeEncriptado = Men.CargaMensajeEncriptado(am);
    	Men.DespliegaMensajeEncriptado(MensajeEncriptado);
    	String MensajePlano = Men.DesencriptaMensajeAES(MensajeEncriptado, Sim.RegresaSimetrica());
    	System.out.println("El siguiente es el mensaje desencriptado que Bob le envio a Alice");
    	Men.DespliegaMensaje(MensajePlano);
    }
}