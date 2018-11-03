package utils;

public class PcapPacketInfo {
	public int etherType;
	
	public String srcIP;
	public String dstIP;
	
	public int ipProto;
	
	public int srcPort;
	public int dstPort;
	
	int payloadOffset = 0;
	int payloadLen = 0;
	byte[] packetBytes = null;
	
	private PcapPacketInfo(byte[] packetBytes)
	{
		this.packetBytes = packetBytes;
	}
	
	public static PcapPacketInfo decode(byte[] packetBytes)
	{
		PcapPacketInfo res = decodeEthernet(packetBytes);
		decodeIP(res);
		decodeTransportLayer(res);
		return res;
	}
	
	public static PcapPacketInfo decodeEthernet(byte[] packetBytes)
	{
		PcapPacketInfo res = new PcapPacketInfo(packetBytes);
		
		res.payloadOffset += 2 * PcapUtils.MAC_ADDRESS_LEN_IN_BYTES;
		res.etherType = 256 * packetBytes[res.payloadOffset] + packetBytes[res.payloadOffset + 1];
					
		if(res.etherType != PcapUtils.ETHER_TYPE_IP)
		{
			//System.out.println("Not IP:" + etherType + " " + payloadOffset + " " + packetBytes.length);
			return null;
		}
		else
		{
			//System.out.println("IP");
			res.payloadOffset += 2;
			return res;
		}
	}

	public static void decodeIP(PcapPacketInfo res)
	{
		if (res != null)
		{
			//ip
			{
				int ipHeaderLen = 4 * (res.packetBytes[res.payloadOffset] & 15);
				int tmpPayloadOffset = res.payloadOffset + 2;
				res.payloadLen = 256 * res.packetBytes[tmpPayloadOffset] + res.packetBytes[tmpPayloadOffset + 1] - ipHeaderLen;
				tmpPayloadOffset += (2 /*len*/ + 4 /*ID, FRAGMENT*/ + 1 /*TTL*/);
				

				res.ipProto = res.packetBytes[tmpPayloadOffset];
/*				System.out.println("ipProto: " + ipProto);
				
				if (res.protocol != PcapUtils.IP_PROTO_TCP && res.roto != PcapUtils.IP_PROTO_UDP)
				{
//					System.out.println("Neither tcp or udp: " + ipProto + " " + tmpPayloadOffset);
					return false;
				}
*/
				
				tmpPayloadOffset += (1 /*protocol*/ + 2 /*checksum*/);
				
				//src ip
				res.srcIP = 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + "." 
							+ 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + "." 
							+ 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + "." 
							+ 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]);
				//dst ip
				res.dstIP =		Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + "." 
							+ 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + "." 
							+ 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + "." 
							+ 	Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]);
				//options
				res.payloadOffset += ipHeaderLen;
			}
			
		}
	}
	
	public static void decodeTransportLayer(PcapPacketInfo res)
	{
		if (res != null)
		{
			if (res.ipProto == PcapUtils.IP_PROTO_TCP)
			{
				decodeTCP(res);
			}
			else if (res.ipProto == PcapUtils.IP_PROTO_UDP)
			{
				decodeUDP(res);
			}
		}
	}
	
	public static void decodeTCP(PcapPacketInfo res)
	{
		if (res != null)
		{
			//ports
			int tmpPayloadOffset = res.payloadOffset;
			
			res.srcPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));			
			res.dstPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));
			
			tmpPayloadOffset += 8;

			int tcpHeaderLen = 4 * (res.packetBytes[tmpPayloadOffset]);
			res.payloadOffset += tcpHeaderLen;
			res.payloadLen -= tcpHeaderLen;
		}
	}
	
	public static void decodeUDP(PcapPacketInfo res)
	{
		if (res != null)
		{
			int tmpPayloadOffset = res.payloadOffset;
			res.srcPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));
			res.dstPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));
			
//			int udpPacketLen = 256 * packetBytes[tmpPayloadOffset++] + packetBytes[tmpPayloadOffset++];
			res.payloadOffset += 8;
			res.payloadLen -= 8;
		}
	}
}
