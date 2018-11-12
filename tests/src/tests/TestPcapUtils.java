package tests;

import org.junit.Test;

import pcap.PcapException;
import pcap.PcapPacketInfo;
import pcap.PcapUtils;

import org.junit.Assert;

public class TestPcapUtils {
	
	@Test
	public void testUDPDecoding()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testPcapPacket);
		Assert.assertNotEquals(null, packet);
		Assert.assertEquals(PcapUtils.ETHER_TYPE_IP, packet.etherType);
		Assert.assertEquals("172.16.121.129", packet.srcIP);
		Assert.assertEquals("172.16.121.2", packet.dstIP);
		Assert.assertEquals(PcapUtils.IP_PROTO_UDP, packet.ipProto);
		Assert.assertEquals(137, packet.srcPort);
		Assert.assertEquals(137, packet.dstPort);
		Assert.assertEquals(42, packet.payloadOffset);
		Assert.assertEquals(68, packet.payloadLen);
		Assert.assertEquals(0, packet.packetStart);
	}
	
	@Test
	public void testTCPDecoding()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testPcapPacketTCP);
		Assert.assertNotEquals(null, packet);
		Assert.assertEquals(PcapUtils.ETHER_TYPE_IP, packet.etherType);
		Assert.assertEquals("127.0.0.1", packet.srcIP);
		Assert.assertEquals("127.0.0.1", packet.dstIP);
		Assert.assertEquals(PcapUtils.IP_PROTO_TCP, packet.ipProto);
		Assert.assertEquals(60706, packet.srcPort);
		Assert.assertEquals(22, packet.dstPort);
		Assert.assertEquals(74, packet.payloadOffset);
		Assert.assertEquals(0, packet.payloadLen);
		Assert.assertEquals(0, packet.packetStart);
	}
	
	@Test
	public void testxxx()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testxxx);
		Assert.assertNotEquals(null, packet);
	}
	
	@Test
	public void test84()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.test84);
		Assert.assertNotEquals(null, packet);
	}
	
	@Test
	public void test88cc()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.test88cc);
		Assert.assertNotEquals(null, packet);
		Assert.assertEquals(PcapUtils.ETHER_TYPE_IP, packet.etherType);
		Assert.assertEquals("64.15.113.142", packet.srcIP);
		Assert.assertEquals("192.168.1.33", packet.dstIP);
		Assert.assertEquals(PcapUtils.IP_PROTO_TCP, packet.ipProto);
		Assert.assertEquals(443, packet.srcPort);
		Assert.assertEquals(16989, packet.dstPort);
		Assert.assertEquals(54, packet.payloadOffset);
		Assert.assertEquals(1460, packet.payloadLen);
		Assert.assertEquals(0, packet.packetStart);
	}
	
	@Test
	public void testIEEE8023()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testIEEE8023);
		Assert.assertNotEquals(null, packet);
	}
	
	//@Test
	public void testDecodingWithOffset()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testPcapPacketWithOffset10, 10, 74);
		Assert.assertNotEquals(null, packet);
		Assert.assertEquals(PcapUtils.ETHER_TYPE_IP, packet.etherType);
		Assert.assertEquals("172.16.121.129", packet.srcIP);
		Assert.assertEquals("172.16.121.2", packet.dstIP);
		Assert.assertEquals(PcapUtils.IP_PROTO_UDP, packet.ipProto);
		Assert.assertEquals(137, packet.srcPort);
		Assert.assertEquals(137, packet.dstPort);
		Assert.assertEquals(68, packet.payloadLen);
		Assert.assertEquals(10, packet.packetStart);
	}
	
	//@Test
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
