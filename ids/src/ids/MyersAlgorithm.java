package ids;

import snortRulesParser.Parser;

public class MyersAlgorithm 
{

	public static boolean Myers(char[] text, int startOffset, int searchLen, char[] pattern)
	{
		return Myers(text, startOffset, searchLen, pattern, 0);
	}
		
	public static boolean Myers(char[] text, int startOffset, int searchLen, char[] pattern, int tollerance)
	{
		int[] bitMask = Parser.createBitmask(pattern);
		return Myers(text, startOffset, searchLen, pattern.length, bitMask, tollerance);		
	}

	public static boolean Myers(char[] text, int startOffset, int searchLen, int patternLength, int[] patternBitmask)
	{
		return Myers(text, startOffset, searchLen, patternLength, patternBitmask, 0);
	}
	
	public static boolean Myers(char[] text, int startOffset, int searchLen, int patternLength, int[] patternBitmask, int tollerance)
	{
		int score = patternLength;
		
		if( text.length < searchLen)
		{
			System.err.println("Invalid searchLen: " + searchLen + " total len: " + text.length);
			return false;
		}
		
		int occurenceCheck = 1 << (patternLength - 1);
		int VP = ~0;
		int VN = 0;
		
		for(int i = startOffset; i < searchLen; i++)
		{			
			char currChar = text[i];
			int X = patternBitmask[currChar] | VN;
				
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
