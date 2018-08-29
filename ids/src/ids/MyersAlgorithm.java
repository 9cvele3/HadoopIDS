package ids;

import snortRulesParser.Parser;

public class MyersAlgorithm {

	public static boolean Myers(char[] text, char[] pattern){
		return Myers(text, pattern, 0);
	}
	
	public static boolean Myers(char[] text, char[] pattern, int tollerance){
		int[] bitMask = Parser.createBitmask(pattern);
		return Myers(text, pattern.length, bitMask, tollerance);		
	}

	public static boolean Myers(char[] text, int patternLength, int[] patternBitmask){
		return Myers(text, patternLength, patternBitmask, 0);
	}
	
	public static boolean Myers(char[] text, int patternLength, int[] patternBitmask, int tollerance){
		int score = patternLength;
		int n = text.length;
		int occurenceCheck = 1 << (patternLength - 1);
		int VP = ~0;
		int VN = 0;
		
		for(int i = 0; i < n; i++){			
			char currChar = text[i];
			int X = patternBitmask[currChar] | VN;
				
			int D0 = ((VP + (X & VP)) ^ VP) | X;
			int HN = VP & D0;
			int HP = VN | ~(VP | D0);
			X  = HP << 1;
			VN = X & D0;
			VP = (HN << 1) | ~(X | D0);
			
			if((HP & occurenceCheck) != 0){
				score++;
			}
			if((HN & occurenceCheck) != 0){
				score--;
			}
			if(score <= tollerance){
				return true;
			}
		}
		return false;
	}
}
