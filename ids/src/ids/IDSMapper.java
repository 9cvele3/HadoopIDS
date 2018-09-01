package ids;

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

	String SourceIP = "";
	String DestIP = "";
	
	Protocol protocol = Protocol.NOT_SUPPORTED;
	
	String SourcePort = "";
	String DestPort = "";
	
	char[] payloadBytes = null;
	
	private final String delimiter = ",";
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
		packetBytes = value.getBytes();

		if (decodePacket())
		{
			checkForPatterns(context);
		}
	}
	
	int payloadOffset = 0;
	Protocol p;
	int payloadLen = 0;
	byte[] packetBytes = null;
	
	final int MAC_ADDRESS_LEN_IN_BYTES = 6;
	final int ETHER_TYPE_IP = 0x0800;
	final int IP_PROTO_TCP = 0x06;
	final int IP_PROTO_UDP = 0x11;
	
	private int convertToUnsignedInt(byte b)
	{
		return b < 0 ? 256 + b : b;
	}
	
	private boolean decodePacket()
	{
		if (packetBytes == null) 
		{
			return false;
		}
		
		payloadOffset = 0;
		payloadLen = 0;
		p = Protocol.NOT_SUPPORTED;
		
		//ethernet
		{
			payloadOffset += 2 * MAC_ADDRESS_LEN_IN_BYTES;
			int etherType = 256 * packetBytes[payloadOffset] + packetBytes[payloadOffset + 1];
			
			if(etherType != ETHER_TYPE_IP)
			{
				//System.out.println("Not IP:" + etherType + " " + payloadOffset + " " + packetBytes.length);
				return false;
			}
			else
			{
				//System.out.println("IP");
				payloadOffset += 2;
			}
		}
		
		int ipProto = 0;
		//ip
		{
			int ipHeaderLen = 4 * (packetBytes[payloadOffset] & 15);
			int tmpPayloadOffset = payloadOffset + 2;
			payloadLen = 256 * packetBytes[tmpPayloadOffset] + packetBytes[tmpPayloadOffset + 1] - ipHeaderLen;
			tmpPayloadOffset += (2 /*len*/ + 4 /*ID, FRAGMENT*/ + 1 /*TTL*/);
			
			ipProto = packetBytes[tmpPayloadOffset];
//			System.out.println("ipProto: " + ipProto);
			
			if (ipProto != IP_PROTO_TCP && ipProto != IP_PROTO_UDP)
			{
//				System.out.println("Neither tcp or udp: " + ipProto + " " + tmpPayloadOffset);
				return false;
			}
			
			tmpPayloadOffset += (1 /*protocol*/ + 2 /*checksum*/);
			
			//src ip
			SourceIP = convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + "." 
						+ convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + "." 
						+ convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + "." 
						+ convertToUnsignedInt(packetBytes[tmpPayloadOffset++]);
			//dst ip
			DestIP =  convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + "." 
						+ convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + "." 
						+ convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + "." 
						+ convertToUnsignedInt(packetBytes[tmpPayloadOffset++]);
			//options
			payloadOffset += ipHeaderLen;
		}
		
		if (ipProto == IP_PROTO_TCP)
		{
			//port, port
			int tmpPayloadOffset = payloadOffset;
			
			SourcePort = "" + (256 * convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + convertToUnsignedInt(packetBytes[tmpPayloadOffset++]));			
			DestPort = ""  + (256 * convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + convertToUnsignedInt(packetBytes[tmpPayloadOffset++]));
			
			tmpPayloadOffset += 8;

			int tcpHeaderLen = 4 * (packetBytes[tmpPayloadOffset]);
			payloadOffset += tcpHeaderLen;
			payloadLen -= tcpHeaderLen;
			p = Protocol.TCP;
		}
		else
		{
			//port, port	
			int tmpPayloadOffset = payloadOffset;
			SourcePort = "" + (256 * convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + convertToUnsignedInt(packetBytes[tmpPayloadOffset++]));
			DestPort = ""  + (256 * convertToUnsignedInt(packetBytes[tmpPayloadOffset++]) + convertToUnsignedInt(packetBytes[tmpPayloadOffset++]));
			
//			int udpPacketLen = 256 * packetBytes[tmpPayloadOffset++] + packetBytes[tmpPayloadOffset++];
			payloadOffset += 8;
			payloadLen -= 8;
			p = Protocol.UDP;
		}
		
		//System.out.println(SourceIP + " " + SourcePort + "  " + DestIP + " " + DestPort);
		return true;
	}
	
	private void checkForPatterns(Context context) throws IOException, InterruptedException {
		
		if(payloadBytes == null) 
		{
			return;		
		}
		
		if(protocol == Protocol.NOT_SUPPORTED) 
		{
			return;
		}
		
		List<Rule> ruleList = rules.get(protocol);
		
		if(ruleList != null && !ruleList.isEmpty()) 
		{
			for(Rule r : ruleList)
			{
				if(r.checkSrcAndDest(SourceIP, DestIP, SourcePort, DestPort) && r.payloadMatch(payloadBytes, payloadOffset, payloadLen))
				{
					context.write(new Text(r.getSid() + delimiter + SourceIP + ":" + r.getSrcPort() + delimiter + DestIP + ":" + r.getDestPort()), ONE);
				}
			}
		}
	}
}
