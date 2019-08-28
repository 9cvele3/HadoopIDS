package pcap;

import utils.Utils;

public class WholePcapPacketInfo{
	PcapPacketInfo pcapPacketInfo;
	byte[] packetData = null;
	
	private WholePcapPacketInfo(byte[] packetData, int offset)
	{
		this.offset = offset;
		this.packetData = packetData;
	}
	
	private WholePcapPacketInfo(byte[] packetData, int offset, int packetLen)
	{
		this.offset = offset;
		pcapPacketInfo = PcapPacketInfo.decodeEthernet(packetData, offset + PcapUtils.PACKET_HEADER_SIZE, packetLen);
	}
	
	public static WholePcapPacketInfo decode(byte[] packetData)
	{
		return decode(packetData, 0);
	}
	
	public static WholePcapPacketInfo decode(byte[] packetData, int offset)
	{
		if (offset + 12 + 4 >= packetData.length )
			return null;
		
		WholePcapPacketInfo res = new WholePcapPacketInfo(packetData, offset);
		
		res.len = Utils.getIntFromByteArray(packetData, offset + 8);
		res.origLen = Utils.getIntFromByteArray(packetData, offset + 12);
		
		if (!res.validBoundary())
			return null;
		
		return res;			
	}
	
	private boolean validBoundary()
	{
		boolean validBoundary = true;
		
		validBoundary &= (origLen > 0);
		validBoundary &= (len <= origLen);
		validBoundary &= (len <= PcapUtils.MAX_PACKET_LEN);
		validBoundary &= (len >= PcapUtils.MIN_PACKET_LEN);
		
		pcapPacketInfo = PcapPacketInfo.decodeEthernet(packetData, offset + PcapUtils.PACKET_HEADER_SIZE, len);
		validBoundary &= (pcapPacketInfo != null);
		
		return validBoundary;
	}
	
	public int len;
	public int origLen;
	private int offset;
}
