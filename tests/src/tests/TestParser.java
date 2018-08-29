package tests;

import org.junit.Test;
import ids.MyersAlgorithm;
import snortRulesParser.Parser;
import org.junit.Assert;

public class TestParser {

	private String ruleExample = "alert tcp $EXTERNAL_NET any -> $HOME_NET 7597 ( msg:\"MALWARE-BACKDOOR QAZ Worm Client Login access\"; flow:to_server,established; content:\"qazwsx.hsq\"; metadata:ruleset community; reference:mcafee,98775; classtype:misc-activity; sid:108; rev:11; )";

	@Test
	public void sidExtraction(){
		Assert.assertEquals("108", Parser.collectSid(ruleExample));
	}
	
	@Test
	public void contentExtraction(){
		Assert.assertEquals("qazwsx.hsq", Parser.collectContent(ruleExample));
	}
	
	@Test
	public void preprocessing(){
		char[] pattern = new char[]{1, 2, 4, 3, 3, 1, 2, 4};
		int[] exBitmask = new int[256];	exBitmask[1]=33; exBitmask[2]=66; exBitmask[3]=24; exBitmask[4]=132;		
		Assert.assertArrayEquals(exBitmask, Parser.createBitmask(pattern));
	}
	
	@Test
	public void byteMatching(){
		char[] text = new char[]{12, 43, 23, 11, 10, 123, 23, 13, 15};
		char[] pattern = new char[]{11, 10, 123, 23};
		Assert.assertTrue(MyersAlgorithm.Myers(text, pattern, 0));
	}
	
	//@Test
	public void parseSingleRule(){
		String expected = "108;tcp;$EXTERNAL_NET;any;$HOME_NET;7597;qazwsx.hsq;";
		String parsed = Parser.parseSingleSnortRule(ruleExample);
		Assert.assertEquals(expected, parsed);
	}
	
	@Test
	public void parseByteDefinedContent(){
		String content = "|0a 1b 2d|abc|3f 4d|";
		char[] expected = new char[] {10, 27, 45, 'a', 'b', 'c', 63, 77};
		Assert.assertArrayEquals(expected, Parser.convertContentToCharArray(content));
	}
	
	@Test
	public void parseByteDefinedAndMatch() {
		String content = "|18 03 02 00|";
		char[] expected = new char[] {24, 3, 2, 0};
		Assert.assertArrayEquals(expected, Parser.convertContentToCharArray(content));
		char[] payload = new char[] {32, 123, 24, 3, 2, 0, 15};
		Assert.assertTrue(MyersAlgorithm.Myers(payload, 4, Parser.createBitmask(expected)));
	}
}
