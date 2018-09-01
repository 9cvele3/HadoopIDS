package snortRulesParser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Parser 
{
	
	public static void main(String[] args) 
	{
		if(args.length != 2)
		{
			System.err.println("Arguments: <input_snort_rule_file> <output_parsed_file>");
			return;
		}
		
		String snortRulesFilePath = args[0];
		String reducedSnortRules  = args[1];
		parseSnortRules(snortRulesFilePath, reducedSnortRules);
		System.out.println("Parser finished!");
	}
	
	public static void parseSnortRules(String rulesFilename, String distributedCashe) 
	{
		File rules = new File(rulesFilename);
		File reduced = new File(distributedCashe);
		
		BufferedReader br = null;
		FileWriter fw = null;
		
		int numParsedRules = 0;
		
		try 
		{
			br = new BufferedReader(new FileReader(rules));
			fw = new FileWriter(reduced);
			
			String readLine = "";
			
			while((readLine = br.readLine()) != null)
			{
				String parsedRule = parseSingleSnortRule(readLine);
				
				if(!parsedRule.isEmpty())
				{
					fw.write(parseSingleSnortRule(readLine));
					fw.write("\n");
					numParsedRules++;
				}
			}

		} 
		catch (FileNotFoundException e1) 
		{
			e1.printStackTrace();
		}
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		finally 
		{
			try 
			{
				if(br != null) 
				{
					br.close();
				}
			}
			catch (IOException e) 
			{
				e.printStackTrace();
			}
			
			try 
			{
				if(fw != null)
				{
					fw.close();
				}
			}
			catch (IOException e) 
			{
				e.printStackTrace();
			}
			
			System.out.println("Parsed rules: " + numParsedRules);
		}
	}
	
	public static String parseSingleSnortRule(String ruleLine) 
	{
		if(ruleLine.isEmpty() || ruleLine.startsWith("#")) 
		{
			return "";
		}
//		System.out.println(ruleLine);
		
		StringBuilder sb = new StringBuilder();
		addNewField(sb, collectSid(ruleLine));
		
		sb.append(collectBasicInformations(ruleLine));
		
		char[] pattern = convertContentToCharArray(collectContent(ruleLine));
		addNewField(sb, String.valueOf(pattern.length));
		addNewField(sb, convertArrayToSemicolonSeparatedString(createBitmask(pattern)));
		
		return sb.toString();
	}
	
	public static String collectSid(String ruleLine)
	{
		String regexSid = "sid:.*?;";
		Pattern pattern = Pattern.compile(regexSid);
		Matcher matcher = pattern.matcher(ruleLine);
		matcher.find();
		int len = matcher.end() - matcher.start();
		return matcher.group().substring(4, len-1);
	}
	
	public static String collectContent(String ruleLine)
	{
		String regexContentType = "content:\".*?\"";
		Pattern pattern = Pattern.compile(regexContentType);
		Matcher matcher = pattern.matcher(ruleLine);
		matcher.find();
		int len = matcher.end() - matcher.start();
		return matcher.group().substring(9, len-1);
	}
	
	public static String convertArrayToSemicolonSeparatedString(int[] array)
	{
		StringBuilder sb = new StringBuilder();
		
		for(int i = 0; i < array.length - 1; i++)
		{
			sb.append(array[i] + ";");
		}
		
		sb.append(array[array.length - 1]);
		return sb.toString();
	}
	
	public static char[] convertContentToCharArray(String content)
	{
		char[] res = new char[content.length()];
		
		int mode = 0; 
		int i = 0, iRes = 0;
	
		while(i < content.length())
		{
			char currChar = content.charAt(i); 
			
			if(currChar == '|')
			{
				mode ^= 1;
				i++;
			}
			else
			{
				if(mode == 0)
				{
					res[iRes++] = currChar;
					i++;
				}
				else
				{
					res[iRes++] = (char) Integer.parseInt(content.substring(i, i+2), 16);
					i += 2;
				
					if(content.charAt(i)==' ')
					{
						i++;
					}
				}
			}
		}
		
		if(iRes == content.length())
		{
			return res;
		}
		else
		{
			char[] returnRes = new char[iRes];
			
			for(int j = 0; j < iRes; j++)
			{
				returnRes[j] = res[j];
			}
			
			return returnRes;
		}
	}
	
	private static String collectBasicInformations(String ruleLine)
	{
		StringBuilder sb = new StringBuilder();
		StringTokenizer tok = new StringTokenizer(ruleLine);
		tok.nextToken();//alert
		addNewField(sb, tok.nextToken());//protocol
		addNewField(sb, tok.nextToken());//src ip
		addNewField(sb, tok.nextToken());//src port
		tok.nextToken();//direction
		addNewField(sb, tok.nextToken());//dest ip
		addNewField(sb, tok.nextToken());//dest port
		
		return sb.toString();
	}
	
	private static void addNewField(StringBuilder sb, String newField)
	{
		sb.append(newField);
		sb.append(';');
	}

	public static int[] createBitmask(char[] pattern) 
	{
		int[] bitmask = new int[256];
		int mask = 1;
	
		for(int iByte = 0; iByte < pattern.length; iByte++)
		{
			bitmask[pattern[iByte]] |= mask;
			mask = mask << 1;
		}
		
		return bitmask;
	}
}