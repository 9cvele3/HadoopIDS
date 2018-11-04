package pcap;

import utils.Utils;

public class WholePcapPacketInfo{
	PcapPacketInfo pcapPacketInfo;
	
	private WholePcapPacketInfo(byte[] packetData)
	{
		offset = 0;
		pcapPacketInfo = PcapPacketInfo.decode(packetData);
	}
	
	private WholePcapPacketInfo(byte[] packetData, int offset)
	{
		this.offset = offset;
		pcapPacketInfo = PcapPacketInfo.decode(packetData, offset + PcapUtils.PACKET_HEADER_SIZE);
	}
	
	public static WholePcapPacketInfo decode(byte[] packetData)
	{
		return decode(packetData, 0);
	}
	
	public static WholePcapPacketInfo decode(byte[] packetData, int offset)
	{
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
		
		validBoundary &= (pcapPacketInfo != null);
		validBoundary &= (origLen > 0);
		validBoundary &= (len <= origLen);
		validBoundary &= (len <= PcapUtils.MAX_PACKET_LEN);
		validBoundary &= (len >= PcapUtils.MIN_PACKET_LEN);
		
		return validBoundary;
	}
	
	public int len;
	public int origLen;
	private int offset;
}
