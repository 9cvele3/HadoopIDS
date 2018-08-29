package ids;

import java.util.StringTokenizer;

public class Rule {
	private String sid;
	private Protocol protocol;
	
	private String srcIP;
	private String srcPort;
	
	private String destIP;
	private String destPort;
	
	private int patternLength;
	
	private int[] bitmask = null;//new int[256];
	
	public Rule(String line){
		StringTokenizer st = new StringTokenizer(line);
		String fieldSeparator = ";";
		sid = st.nextToken(fieldSeparator);
		protocol = Protocol.getProtocol(st.nextToken(fieldSeparator));
		
		srcIP = st.nextToken(fieldSeparator);
		srcPort = st.nextToken(fieldSeparator);
		
		destIP = st.nextToken(fieldSeparator);
		destPort = st.nextToken(fieldSeparator);
		
		patternLength = Integer.parseInt(st.nextToken(fieldSeparator));
		if(patternLength != 0) {
			bitmask = new int[256];
			for(int i = 0; i < 256; i++)
				bitmask[i] = Integer.parseInt(st.nextToken(fieldSeparator));
		}
	}
	
	public boolean checkSrcAndDest(String SrcIP, String DestIP, String SrcPort, String DestPort) {
		return 
					(srcIP.equalsIgnoreCase("any") 		|| srcIP.equalsIgnoreCase(SrcIP))
				&&	(destIP.equalsIgnoreCase("any") 	|| destIP.equalsIgnoreCase(DestIP))
				&&	(srcPort.equalsIgnoreCase("any") 	|| srcPort.equalsIgnoreCase(SrcPort))
				&&	(destPort.equalsIgnoreCase("any") 	|| destPort.equalsIgnoreCase(DestPort));
	}
	
	public boolean payloadMatch(char[] packetPayload){
		if(patternLength == 0)  return true;
		return MyersAlgorithm.Myers(packetPayload, patternLength, bitmask);
	}
	
	public String getSid() { return sid; }
	public Protocol getProtocol() {return protocol;}
	public String getSrcIP() { return srcIP; }
	public String getSrcPort() { return srcPort; }
	public String getDestIP() { return destIP; }
	public String getDestPort() { return destPort; }
	public int getPatternLength() { return patternLength;}
}
