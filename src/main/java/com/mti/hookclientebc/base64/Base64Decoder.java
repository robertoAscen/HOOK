package base64;

public class Base64Decoder 
{
	public byte[] decodeBuffer(String base64) 
	{
		return Base64.decode(base64);
	}
}
