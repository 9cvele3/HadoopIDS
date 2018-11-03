package ids;
import utils.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Mapper;

public class IDSMapper extends Mapper<LongWritable, BytesWritable, Text, LongWritable> 
{
	HashMap<Protocol, List<Rule>> rules = new HashMap<Protocol, List<Rule>>();
		
	String delimiter = ", "; //Used for Reduce key formation
	
	private final LongWritable ONE = new LongWritable(1);
	
	@Override
	protected void setup(Context context) throws IOException 
	{
		BufferedReader bfr = new BufferedReader(new FileReader(new File("cached-rules.txt")));
		
		String line;
		
		while((line = bfr.readLine()) != null) 
		{
//			System.out.println(line);
			Rule r = new Rule(line);
			Protocol rProto = r.getProtocol();
			
			if(rules.containsKey(rProto))
			{
				rules.get(rProto).add(r);
			}
			else 
			{
				ArrayList<Rule> ruleList = new ArrayList<Rule>();
				ruleList.add(r);
				rules.put(rProto, ruleList);
			}
		}
		
		bfr.close();
	}
	
	@Override
	public void map(LongWritable key, BytesWritable value, Context context) 
			throws IOException, InterruptedException 
	{
		byte[] packetBytes = value.getBytes();
		PcapPacketInfo packet = PcapPacketInfo.decode(packetBytes);
		checkForPatterns(context);
	}
	
	private void checkForPatterns(Context context) throws IOException, InterruptedException {

//		System.out.println("checkForPatterns");
		
		if(packetBytes == null) 
		{
			System.out.println("packetBytes is null");
			return;		
		}
		
		if(protocol == Protocol.NOT_SUPPORTED) 
		{
			System.out.println("Protocol is not supported");
			return;
		}
		
		List<Rule> ruleList = rules.get(protocol);
		
		if(ruleList != null && !ruleList.isEmpty()) 
		{
			for(Rule r : ruleList)
			{
				if (
							r.checkSrcAndDest(SourceIP, DestIP, SourcePort, DestPort) 
						&& 	r.payloadMatch(packetBytes)/*, payloadOffset, payloadLen)*/
					)
				{
					context.write(new Text(r.getSid() + delimiter + SourceIP + ":" + r.getSrcPort() + delimiter + DestIP + ":" + r.getDestPort()), ONE);
				}
			}
		}
	}
	
	private Text getReducerKey(PcapPacketInfo packet)
	{
		return new Text();
	}
}
