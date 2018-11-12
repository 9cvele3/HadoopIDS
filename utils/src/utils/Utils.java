package utils;

public final class Utils {
	public static char convertToChar(byte b)
	{
		return b < 0 ? (char) (256 + b) : (char)b;
	}
	
	public static int convertToUnsignedInt(byte b)
	{
		return b < 0 ? (256 + b) : b;
	}
	
	
	/**
	 * Converts big endian int to little endian int
	 * @param bigEndian - 32b int big endian value
	 * @return 32b int little endian value
	 */
	public static int ntohl(int bigEndian)
	{
		int littleEndian = 0;
		
		for(int i = 0; i < 4; i++)
		{
			littleEndian = littleEndian << 8;
			littleEndian |= (bigEndian & 0xff);
			bigEndian = bigEndian >> 8;
		}
		
		return littleEndian;
	}
	
	/**
	 * Converts big endian short to little endian short
	 * @param bigEndian - 16b short big endian value
	 * @return 16b short little endian value
	 */
	public static short ntohs(short bigEndian)
	{
		short littleEndian = 0;
		littleEndian |= (bigEndian & 0xff);
		littleEndian = (short) (littleEndian << 8);
		bigEndian = (short) (bigEndian >> 8);
		littleEndian |= (bigEndian & 0xff);
		return littleEndian;
	}
	
	/*
	 * Gets int value from bytes arr at position offset.
	 */
	public static int getIntFromByteArray(byte[] arr, int offset)
	{
		int res = convertToUnsignedInt(arr[offset + 3]) 	<< 8;		//System.out.print(" " + res);
		res = (res + convertToUnsignedInt(arr[offset + 2])) << 8;		//System.out.print(" " + res);
		res = (res + convertToUnsignedInt(arr[offset + 1])) << 8;		//System.out.print(" " + res);
		res = (res + convertToUnsignedInt(arr[offset]));				//System.out.print(" " + res);
		
		return res;
	}

	public static void displayArray(byte[] arr)
	{
		System.out.print("Array: ");
		
		for (int i = 0; i < arr.length; i++)
		{
			System.out.print(" " + arr[i]);
		}
		
		System.out.println();
	}
}
