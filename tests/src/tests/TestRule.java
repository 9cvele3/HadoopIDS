package tests;

import org.junit.Test;
import snortRulesParser.Parser;
import ids.Protocol;
import ids.Rule;
import org.junit.Assert;

public class TestRule {
	private String ruleExample = "alert tcp $EXTERNAL_NET any -> $HOME_NET 7597 ( msg:\"MALWARE-BACKDOOR QAZ Worm Client Login access\"; flow:to_server,established; content:\"qazwsx.hsq\"; metadata:ruleset community; reference:mcafee,98775; classtype:misc-activity; sid:108; rev:11; )";
	private String ruleExampleBytes = "alert tcp any any -> any 443 (msg:\"Heartbeat request\"; content:\"|18 03 02 00|\"; sid:100000;)";
	
	@Test
	public void RuleCreation(){
		String parsedRule = Parser.parseSingleSnortRule(ruleExample);
		Rule rule = new Rule(parsedRule);
		Assert.assertEquals("108", rule.getSid());
		Assert.assertEquals(Protocol.TCP, rule.getProtocol());
	}
	
	@Test
	public void RuleMatching(){
		String payload = "asdfvafasdqazwsx.hsqasdfadsf";
		Rule rule = new Rule(Parser.parseSingleSnortRule(ruleExample));
		Assert.assertTrue(rule.payloadMatch(payload.toCharArray()));
	}
	
	@Test
	public void RuleMatchingBytes() {
		char[] payload = new char[] {24, 3, 2, 0};
		Rule rule = new Rule(Parser.parseSingleSnortRule(ruleExampleBytes));
		Assert.assertTrue(rule.payloadMatch(payload));
	}
	
	@Test
	public void RuleMatchingBytes2() {
		//char[] payload = new char[] {24, 3, 2, 0};
		byte[] payload = new byte[] { 0x00, 0x0c, 0x29, 0x15, (byte)0xf3, (byte)0xe9, 0x00, 0x50, 
				0x56, (byte)0xc0, 0x00, 0x08, 0x08, 0x00, 0x45, 0x00,
				0x00, 0x3c, 0x58, (byte)0xeb, 0x40, 0x00, 0x40, 0x06, 
				(byte)0x97, 0x18, (byte)0xac, 0x10, 0x79, 0x01, (byte)0xac, 0x10,
				0x79, (byte)0x96, (byte)0xfc, (byte)0x9b, 0x01, (byte)0xbb, (byte)0xee, (byte)0xe0, 
				(byte)0xa5, 0x10, (byte)0xd2, 0x3b, 0x4b, (byte)0xd2, (byte)0x80, 0x18,
				0x20, 0x00, 0x3c, (byte)0xfa, 0x00, 0x00, 0x01, 0x01, 
				0x08, 0x0a, 0x2a, 0x72, (byte)0x9e, (byte)0xb8, 0x00, 0x24,
				(byte)0xf8, 0x50, 0x18, 0x03, 0x02, 0x00, 0x03, 0x01,
				0x40, 0x00
		};
		Rule rule = new Rule(Parser.parseSingleSnortRule(ruleExampleBytes));
		Assert.assertTrue(rule.payloadMatch(payload));
	}
}
