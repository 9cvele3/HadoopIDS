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
}
