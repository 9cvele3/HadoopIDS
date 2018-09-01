package ids;

public enum Protocol {

	TCP,
	UDP,
	NOT_SUPPORTED;
	
	public static Protocol getProtocol(String protocolName) {
		
		if(protocolName.equalsIgnoreCase("tcp"))
		{
			return Protocol.TCP;
		}
		
		if(protocolName.equalsIgnoreCase("udp")) 
		{
			return Protocol.UDP;
		}
		
		return Protocol.NOT_SUPPORTED;
	}
}
