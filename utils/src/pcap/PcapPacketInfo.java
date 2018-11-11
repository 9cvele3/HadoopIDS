package pcap;

import utils.Utils;

public class PcapPacketInfo {
	public int etherType;
	
	public String srcIP;
	public String dstIP;
	
	public int ipProto;
	
	public int srcPort;
	public int dstPort;
	
	public int packetStart = 0;
	public int payloadOffset = 0;
	public int payloadLen = 0;
	public byte[] packetBytes = null;
	
	private PcapPacketInfo(byte[] packetBytes)
	{
		this.packetBytes = packetBytes;
	}
	
	private PcapPacketInfo(byte[] packetBytes, int packetStart)
	{
		this.packetBytes = packetBytes;
		this.packetStart = packetStart;
		this.payloadOffset = packetStart;
	}
	
	public static PcapPacketInfo decode(byte[] packetBytes)
	{
		return decode(packetBytes, 0);
	}
	
	public static PcapPacketInfo decode(byte[] packetBytes, int packetStart)
	{
		PcapPacketInfo res = decodeEthernet(packetBytes, packetStart);
		decodeIP(res);
		decodeTransportLayer(res);
		return res;		
	}
	
	public static PcapPacketInfo decodeEthernet(byte[] packetBytes)
	{
		return decodeEthernet(packetBytes, 0);
	}
	
	public static PcapPacketInfo decodeEthernet(byte[] packetBytes, int offset)
	{
		PcapPacketInfo res = new PcapPacketInfo(packetBytes, offset);
		
		res.payloadOffset += 2 * PcapUtils.MAC_ADDRESS_LEN_IN_BYTES;
		res.etherType = 256 * packetBytes[res.payloadOffset] + packetBytes[res.payloadOffset + 1];
					
		if(!PcapUtils.checkEtherType(res.etherType))
		{
			return null;
		}
		else
		{
			res.payloadOffset += 2;
			return res;
		}
	}

	public static void decodeIP(PcapPacketInfo res)
	{
		if (res != null && res.etherType == PcapUtils.ETHER_TYPE_IP)
		{
			//ip
			{
				int ipHeaderLen = 4 * (res.packetBytes[res.payloadOffset] & 15);
				int tmpPayloadOffset = res.payloadOffset + 2;
				res.payloadLen = 256 * res.packetBytes[tmpPayloadOffset] + res.packetBytes[tmpPayloadOffset + 1] - ipHeaderLen;
				tmpPayloadOffset += (2 /*len*/ + 4 /*ID, FRAGMENT*/ + 1 /*TTL*/);
				

				res.ipProto = res.packetBytes[tmpPayloadOffset];
//				System.out.println("ipProto: " + ipProto);
				
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
