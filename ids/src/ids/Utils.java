package ids;

public final class Utils {
	public static char convertToChar(byte b)
	{
		return b < 0 ? (char) (256 + b) : (char)b;
	}
	
	public static int convertToUnsignedInt(byte b)
	{
		return b < 0 ? (256 + b) : b;
	}
}
