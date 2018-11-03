package tests;

import org.junit.Test;
import org.junit.Assert;
import utils.*;

public class TestPcapUtils {
	
	@Test
	public void testDecoding()
	{
		PcapPacketInfo packet = PcapPacketInfo.decode(Packets.testPcapPacket);
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
		
	}
}
