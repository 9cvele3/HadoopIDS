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

import pcap.PcapPacketInfo;
import pcap.PcapUtils;

public class IDSMapper extends Mapper<LongWritable, BytesWritable, Text, LongWritable> 
{
	HashMap<Integer, List<Rule>> tcpRules = new HashMap<Integer, List<Rule>>();
	HashMap<Integer, List<Rule>> udpRules = new HashMap<Integer, List<Rule>>();

	private final String delimiter = ", "; //Used for Reduce key formation
	
	private final LongWritable ONE = new LongWritable(1);
	private final Integer ZERO = new Integer(0);
	private Text outputKey = new Text();
	
	private void addRule(HashMap<Integer, List<Rule>> rules, Rule r)
	{
		Integer destPort = r.getDestPortInt();
		
		if (rules.containsKey(destPort))
		{
			rules.get(destPort).add(r);
		}
		else 
		{
			ArrayList<Rule> ruleList = new ArrayList<Rule>();
			ruleList.add(r);
			rules.put(destPort, ruleList);
		}
	}
	
	@Override
	protected void setup(Context context) throws IOException 
	{
		BufferedReader bfr = new BufferedReader(new FileReader(new File("cached-rules.txt")));
		
		String line;
		
		while((line = bfr.readLine()) != null) 
		{
			Rule r = new Rule(line);
			Protocol rProto = r.getProtocol();
			
			if (rProto == Protocol.TCP)
			{
				addRule(tcpRules, r);
			}
			else if (rProto == Protocol.UDP)
			{
				addRule(udpRules, r);
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
		
		if (packet != null)
		{
			checkForPatterns(packet, context);
		}
	}
	
	private void checkForPatterns(PcapPacketInfo packet, Context context) 
			throws IOException, InterruptedException 
	{
		assert packet != null;
		
		List<Rule> ruleList = null;		// rules for specific protocol and destination port
		List<Rule> ruleListAny = null;	// rules for specific protocol and 'any' destination port
		
		if (packet.ipProto == PcapUtils.IP_PROTO_TCP)
		{
			ruleList = tcpRules.get(packet.dstPort);
			ruleListAny = tcpRules.get(ZERO);
		}
		else if (packet.ipProto == PcapUtils.IP_PROTO_UDP)
		{
			ruleList = udpRules.get(packet.dstPort);
			ruleListAny = udpRules.get(ZERO);
		}
		else 
		{
			//System.out.println("Protocol is not supported: " + packet.ipProto);
			return;
		}
		
		checkAgainstList(ruleList, packet, context);
		checkAgainstList(ruleListAny, packet, context);
	}
	
	private void checkAgainstList(List<Rule> ruleList, PcapPacketInfo packet, Context context)
			throws IOException, InterruptedException
	{
		if (ruleList != null && !ruleList.isEmpty()) 
		{
			for (Rule r : ruleList)
			{
				if (r.checkAgainstPacket(packet))
				{
					outputKey.set(r.getSid() + delimiter + packet.srcIP + ":" 
							+ 	r.getSrcPort() + delimiter + packet.dstIP 
							+ 	":" + r.getDestPort());
					
					context.write(outputKey, ONE);
				}
			}
		}
	}
}
