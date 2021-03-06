package ids;

import snortRulesParser.Parser;
import utils.Utils;

public final class MyersAlgorithm
{
// Generics in Java do not support primitive types. Separate code for char and for byte.
	
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CHAR
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	public static boolean Myers(char[] text, int startOffset, int searchLen, char[] pattern)
	{
		int tollerance = 0;
		return Myers(text, startOffset, searchLen, pattern, tollerance);
	}
		
	public static boolean Myers(char[] text, int startOffset, int searchLen, char[] pattern, int tollerance)
	{
		int[] bitMask = Parser.createBitmask(pattern);
		return Myers(text, startOffset, searchLen, pattern.length, bitMask, tollerance);		
	}

	public static boolean Myers(char[] text, int startOffset, int searchLen, int patternLength, int[] patternBitmask)
	{
		int tollerance = 0;
		return Myers(text, startOffset, searchLen, patternLength, patternBitmask, tollerance);
	}
	
	public static boolean Myers(char[] text, int startOffset, int searchLen, int patternLength, int[] patternBitmask, int tollerance)
	{
		int score = patternLength;
		
		//System.out.println("Myers: " + startOffset + " " + searchLen + " text.len: " + text.length);
		
		if (
				text.length < searchLen + startOffset
				|| startOffset >= text.length
				|| startOffset < 0
				|| searchLen < 0
			)
		{
			return false;
		}
		
		int occurenceCheck = 1 << (patternLength - 1);
		int VP = ~0;
		int VN = 0;
		
		for(int i = startOffset; i < startOffset + searchLen; i++)
		{			
			char currChar = text[i];
			int X = patternBitmask[(int) currChar] | VN;
				
			int D0 = ((VP + (X & VP)) ^ VP) | X;
			int HN = VP & D0;
			int HP = VN | ~(VP | D0);
			X  = HP << 1;
			VN = X & D0;
			VP = (HN << 1) | ~(X | D0);
			
			if((HP & occurenceCheck) != 0)
			{
				score++;
			}
			
			if((HN & occurenceCheck) != 0)
			{
				score--;
			}
			
			if(score <= tollerance)
			{
//				System.out.println("Myers found");
				return true;
			}
		}
		
//		System.out.println("Myers not found");
		return false;
	}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//BYTE
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public static boolean Myers(byte[] text, int startOffset, int searchLen, int patternLength, int[] patternBitmask)
	{
		int tollerance = 0;
		return Myers(text, startOffset, searchLen, patternLength, patternBitmask, tollerance);
	}

	public static boolean Myers(byte[] text, int startOffset, int searchLen, int patternLength, int[] patternBitmask, int tollerance)
	{
		int score = patternLength;
		
		//System.out.println("Myers: " + startOffset + " " + searchLen + " text.len: " + text.length);
		
		if (
				text.length < searchLen + startOffset
				|| startOffset >= text.length
				|| startOffset < 0
				|| searchLen < 0
			)
		{
			return false;
		}
		
		int occurenceCheck = 1 << (patternLength - 1);
		int VP = ~0;
		int VN = 0;
		
		for(int i = startOffset; i < startOffset + searchLen; i++)
		{			
			char currChar = Utils.convertToChar(text[i]);
			int X = patternBitmask[(int) currChar] | VN;
				
			int D0 = ((VP + (X & VP)) ^ VP) | X;
			int HN = VP & D0;
			int HP = VN | ~(VP | D0);
			X  = HP << 1;
			VN = X & D0;
			VP = (HN << 1) | ~(X | D0);
			
			if((HP & occurenceCheck) != 0)
			{
				score++;
			}
			
			if((HN & occurenceCheck) != 0)
			{
				score--;
			}
			
			if(score <= tollerance)
			{
//				System.out.println("Myers found");
				return true;
			}
		}
		
//		System.out.println("Myers not found");
		return false;
	}
}
