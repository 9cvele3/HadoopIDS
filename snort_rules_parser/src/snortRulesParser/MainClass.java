package snortRulesParser;

public class MainClass {

	public static void main(String[] args) {
		if(args.length != 2)
		{
			System.err.println("Arguments: <input_snort_rule_file> <output_parsed_file>");
			return;
		}
		
		String snortRulesFilePath = args[0];
		String reducedSnortRules  = args[1];
		
		Parser.parseSnortRules(snortRulesFilePath, reducedSnortRules);
		
		System.out.println("Parser finished!");
	}

}
