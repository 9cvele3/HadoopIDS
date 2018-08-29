package ids;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Mapper;

public class IDSMapper extends Mapper<LongWritable, Text, Text, LongWritable> {
	HashMap<Protocol, List<Rule>> rules = new HashMap<Protocol, List<Rule>>();

	String SourceIP = "";
	String DestIP = "";
	
	Protocol protocol = Protocol.NOT_SUPPORTED;
	
	String SourcePort = "";
	String DestPort = "";
	
	char[] payloadBytes = null;
	
	private final String delimiter = ",";
	private final LongWritable ONE = new LongWritable(1);
	
	@Override
	protected void setup(Context context) throws IOException {
		BufferedReader bfr = new BufferedReader(new FileReader(new File("cached-rules.txt")));
		
		String line;
		while((line = bfr.readLine()) != null) {
//			System.out.println(line);
			Rule r = new Rule(line);
			Protocol rProto = r.getProtocol();
			
			if(rules.containsKey(rProto))
				rules.get(rProto).add(r);
			else {
				ArrayList<Rule> ruleList = new ArrayList<Rule>();
				ruleList.add(r);
				rules.put(rProto, ruleList);
			}
		}
		
		bfr.close();
	}
	
	@Override
	public void map(LongWritable key, Text value, Context context) throws IOException, InterruptedException {
		String line = value.toString();
		parsePacket(line);
		checkForPatterns(context);
	}
	
	private void parsePacket(String line) {
		StringTokenizer st = new StringTokenizer(line);

		try{
			SourceIP = st.nextToken(delimiter);
			DestIP = st.nextToken(delimiter);
		
			String proto = st.nextToken(delimiter);
			protocol = Protocol.getProtocol(proto);

			SourcePort = st.nextToken(delimiter);
			DestPort = st.nextToken(delimiter);
		
			String payloadString = st.nextToken(delimiter);
			payloadBytes = new char[payloadString.length() / 2];
			
			for(int i = 0, iRes = 0; i < payloadString.length(); i+=2, iRes++) {
				payloadBytes[iRes] = (char)Integer.parseInt(payloadString.substring(i, i+2), 16);
			}
		}
		catch(NoSuchElementException exc){
//			System.out.println("No such element");
			payloadBytes = null;
		}
	}
	
	private void checkForPatterns(Context context) throws IOException, InterruptedException {
		if(payloadBytes == null) return;		
		if(protocol == Protocol.NOT_SUPPORTED) return;
		List<Rule> ruleList = rules.get(protocol);
		if(ruleList != null && !ruleList.isEmpty()) {
			for(Rule r : ruleList)
				if(r.checkSrcAndDest(SourceIP, DestIP, SourcePort, DestPort) && r.payloadMatch(payloadBytes))
					context.write(new Text(r.getSid() + delimiter + SourceIP + ":" + r.getSrcPort() + delimiter + DestIP + ":" + r.getDestPort()), ONE);
		}
	}
}
