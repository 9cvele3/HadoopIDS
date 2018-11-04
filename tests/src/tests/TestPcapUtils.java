package tests;

import org.junit.Test;

import pcap.PcapException;
import pcap.PcapPacketInfo;
import pcap.PcapUtils;

import org.junit.Assert;

public class TestPcapUtils {
	
	@Test
	public void testDecoding()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testPcapPacket);
		Assert.assertNotEquals(null, packet);
		Assert.assertEquals(PcapUtils.ETHER_TYPE_IP, packet.etherType);
		Assert.assertEquals("172.16.121.129", packet.srcIP);
		Assert.assertEquals("172.16.121.2", packet.dstIP);
		Assert.assertEquals(PcapUtils.IP_PROTO_UDP, packet.ipProto);
		Assert.assertEquals(137, packet.srcPort);
		Assert.assertEquals(137, packet.dstPort);
	}
	
	@Test
	public void testDecodingWithOffset()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testPcapPacketWithOffset10, 10);
		Assert.assertNotEquals(null, packet);
		Assert.assertEquals(PcapUtils.ETHER_TYPE_IP, packet.etherType);
		Assert.assertEquals("172.16.121.129", packet.srcIP);
		Assert.assertEquals("172.16.121.2", packet.dstIP);
		Assert.assertEquals(PcapUtils.IP_PROTO_UDP, packet.ipProto);
		Assert.assertEquals(137, packet.srcPort);
		Assert.assertEquals(137, packet.dstPort);		
	}
	
	@Test
	public void testHeuristic()
	{
		try {
			Assert.assertEquals(24, PcapUtils.seekForBoundary(Packets.testSequence));
		} catch (PcapException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
