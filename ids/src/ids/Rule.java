package ids;
import utils.Protocol;

import java.io.IOException;
import java.util.StringTokenizer;

import pcap.PcapPacketInfo;

public class Rule 
{
	private String sid;
	private Protocol protocol;
	
	private String srcIP;
	private String srcPort;
	
	private String destIP;
	private String destPort;
	
	private int patternLength;
	
	private int[] bitmask = null;//new int[256];
	
	public Rule(String line)
	{
		StringTokenizer st = new StringTokenizer(line);
		String fieldSeparator = ";";
		sid = st.nextToken(fieldSeparator);
		protocol = Protocol.getProtocol(st.nextToken(fieldSeparator));
		
		srcIP = st.nextToken(fieldSeparator);
		srcPort = st.nextToken(fieldSeparator);
		
		destIP = st.nextToken(fieldSeparator);
		destPort = st.nextToken(fieldSeparator);
		
		patternLength = Integer.parseInt(st.nextToken(fieldSeparator));
		
		if(patternLength != 0) 
		{
			bitmask = new int[256];
		
			for(int i = 0; i < 256; i++)
			{
				bitmask[i] = Integer.parseInt(st.nextToken(fieldSeparator));
			}
		}
	}
	
	public boolean checkSrcAndDest(String SrcIP, String DestIP, String SrcPort, String DestPort) 
	{
		return
					(srcPort.equalsIgnoreCase("any") 	|| srcPort.equalsIgnoreCase(SrcPort))
				&&	(destPort.equalsIgnoreCase("any") 	|| destPort.equalsIgnoreCase(DestPort))
				&&	(srcIP.equalsIgnoreCase("any") 		|| srcIP.equalsIgnoreCase(SrcIP))
				&&	(destIP.equalsIgnoreCase("any") 	|| destIP.equalsIgnoreCase(DestIP));
	}
	
	public boolean payloadMatch(byte[] packetPayload, int payloadOffset, int payloadLen)
	{
		if (patternLength == 0)
		{
			return true;
		}
		else
		{
			return MyersAlgorithm.Myers(packetPayload, payloadOffset, payloadLen, patternLength, bitmask);
		}
	}
	
	public boolean payloadMatch(byte[] packetPayload)
	{
		return payloadMatch(packetPayload, 0, packetPayload.length);
	}

	public boolean checkAgainstPacket(PcapPacketInfo packet) 
			throws IOException
	{
		if (packet.payloadLen < 0)
			throw new IOException("payloadLen invalid");
		
		return		checkSrcAndDest(packet.srcIP, packet.dstIP, Integer.toString(packet.srcPort), Integer.toString(packet.dstPort)) 
				&& 	payloadMatch(packet.packetBytes, packet.payloadOffset, packet.payloadLen);
	}
	
	public String getSid() { return sid; }
	public Protocol getProtocol() {return protocol;}
	public String getSrcIP() { return srcIP; }
	public String getSrcPort() { return srcPort; }
	public String getDestIP() { return destIP; }
	public String getDestPort() { return destPort; }
	
	// Returns 0 if destPort is 'any'
	public Integer getDestPortInt() 
	{ 
		int tmp = 0;
		
		try
		{
			tmp = Integer.parseInt(destPort);
		}
		catch(Exception exc)
		{}
		
		return tmp;
	}
	
	public int getPatternLength() { return patternLength;}
	
}
