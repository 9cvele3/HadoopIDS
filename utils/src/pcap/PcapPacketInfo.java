package pcap;

import utils.Utils;

public class PcapPacketInfo {
	public int etherType;
	
	public String srcIP;
	public String dstIP;
	
	public int ipProto;
	
	public int srcPort;
	public int dstPort;
	
	public int packetStart;
	public int payloadOffset;
	public int payloadLen;
	public int packetLen;
	public byte[] packetBytes;
	
	private PcapPacketInfo(byte[] packetBytes)
	{
		assert packetBytes != null;
		
		this.packetBytes = packetBytes;
		this.packetStart = 0;
		this.payloadOffset = 0;
		this.payloadLen = 0;
		this.packetLen = packetBytes.length;
	}
	
	private PcapPacketInfo(byte[] packetBytes, int packetStart, int packetLen)
	{
		assert packetStart >= 0;
		assert packetBytes != null;
		
		this.packetBytes = packetBytes;
		this.packetStart = packetStart;
		this.payloadOffset = packetStart;
		this.payloadLen = 0;
		this.packetLen = packetLen;
	}
	
	public static PcapPacketInfo decode(byte[] packetBytes)
	{
		return decode(packetBytes, 0, packetBytes.length);
	}
	
	public static PcapPacketInfo decode(byte[] packetBytes, int packetStart, int packetLen)
	{
		PcapPacketInfo res = decodeEthernet(packetBytes, packetStart, packetLen);
		
		try
		{
			decodeIP(res);
			decodeTransportLayer(res);
		}
		catch (PcapException pcapExc)
		{
			res = null;
		}
		
		return res;		
	}
	
	public static PcapPacketInfo decodeEthernet(byte[] packetBytes)
	{
		return decodeEthernet(packetBytes, 0, packetBytes.length);
	}
	
	public static PcapPacketInfo decodeEthernet(byte[] packetBytes, int offset, int packetLen)
	{
		PcapPacketInfo res = new PcapPacketInfo(packetBytes, offset, packetLen);
		
		res.payloadOffset += 2 * PcapUtils.MAC_ADDRESS_LEN_IN_BYTES;
		
		if (res.payloadOffset + 1 >= packetBytes.length )
			return null;
		
		res.etherType = 256 * Utils.convertToUnsignedInt(packetBytes[res.payloadOffset])
						+ Utils.convertToUnsignedInt(packetBytes[res.payloadOffset + 1]);
					
		if (
				PcapUtils.checkEtherType(res.etherType) //Eth II
				|| res.checkIEEE8023()
			)
		{
			res.payloadOffset += 2;
			return res;
		}
		else
		{
//			System.out.println("etherType invalid (neither of the two): " + res.etherType);
			return null;
		}
	}

	private boolean checkIEEE8023()
	{
		boolean res = etherType < 1500;
		
		if (etherType < 60)
			res &= (etherType <= packetLen - 2 * PcapUtils.MAC_ADDRESS_LEN_IN_BYTES  - 2);//padding
		else
			res &= (etherType == packetLen - 2 * PcapUtils.MAC_ADDRESS_LEN_IN_BYTES  - 2);//no padding

//		System.out.println("" + etherType  + " " + packetLen + " "+ res);
		return res;
	}
	public static void decodeIP(PcapPacketInfo res) throws PcapException
	{
		if (res != null && res.etherType == PcapUtils.ETHER_TYPE_IP)
		{
			//ip
			{
				int ipHeaderLen = 4 * (Utils.convertToUnsignedInt(res.packetBytes[res.payloadOffset]) & 15);
				int tmpPayloadOffset = res.payloadOffset + 2;
				
				res.payloadLen = 256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset])
									+ Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset + 1])
									- ipHeaderLen;
				
//				System.out.println("" + res.payloadLen + " " + res.packetBytes[tmpPayloadOffset] + " " 
//										+ res.packetBytes[tmpPayloadOffset + 1] + " " + ipHeaderLen);
				tmpPayloadOffset += (2 /*len*/ + 4 /*ID, FRAGMENT*/ + 1 /*TTL*/);
				

				res.ipProto = Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset]);
//				System.out.println("ipProto: " + res.ipProto + " payloadLen: " + res.payloadLen);
				
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
				
				//check
				res.check();
			}
		}
	}
	
	public static void decodeTransportLayer(PcapPacketInfo res) throws PcapException
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
	
	public static void decodeTCP(PcapPacketInfo res) throws PcapException
	{
		if (res != null && res.ipProto == PcapUtils.IP_PROTO_TCP)
		{
			//ports
			int tmpPayloadOffset = res.payloadOffset;
			
			res.srcPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));			
			res.dstPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));
			
			tmpPayloadOffset += 8;

			int tcpHeaderLen = Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset]);
			tcpHeaderLen = tcpHeaderLen >> 4; //top 4 bits, not all 8
			tcpHeaderLen *= 4;
				
			res.payloadOffset += tcpHeaderLen;
			res.payloadLen -= tcpHeaderLen;
			
			res.check();
		}
	}
	
	public static void decodeUDP(PcapPacketInfo res) throws PcapException
	{
		if (res != null && res.ipProto == PcapUtils.IP_PROTO_UDP)
		{
			int tmpPayloadOffset = res.payloadOffset;
			res.srcPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));
			res.dstPort = (256 * Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]) + Utils.convertToUnsignedInt(res.packetBytes[tmpPayloadOffset++]));
			
//			int udpPacketLen = 256 * packetBytes[tmpPayloadOffset++] + packetBytes[tmpPayloadOffset++];
			res.payloadOffset += 8;
			res.payloadLen -= 8;
			
			res.check();
		}
	}
	
	private void check() throws PcapException
	{
		/*
		assert payloadLen >= 0;
		assert payloadOffset >= 0;
		assert packetStart >= 0;
		assert payloadLen <= packetBytes.length;
		*/
		if (payloadLen < 0 || payloadOffset < 0 || packetStart < 0 || payloadLen > packetBytes.length)
		{
			throw new PcapException("Invalid packet!");
			//Utils.displayArray(packetBytes);
			/*
			System.out.println(
					"Decode check" 
				+ "payloadLen: " + payloadLen 
				+ " payloadOffset: " + payloadOffset 
				+ " packetStart: " + packetStart
				+ " payloadLen: " + payloadLen
				+ " packetBytes.len: " + packetBytes.length
					);
					*/
		}
	}
}
