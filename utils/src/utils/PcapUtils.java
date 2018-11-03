package utils;

public final class PcapUtils {
	public final static int MAC_ADDRESS_LEN_IN_BYTES = 6;
	public final static int ETHER_TYPE_IP = 0x0800;
	public final static int IP_PROTO_TCP = 0x06;
	public final static int IP_PROTO_UDP = 0x11;
	
	public static boolean checkEtherType(int ethertype)
	{
		boolean res = false;
		
		for (int i = 0; i < etherTypes.length; i++)
		{
			if (etherTypes[i] == ethertype)
			{
				res = true;
				break;
			}
		}
		
		//System.out.println("check: " + ethertype + " etherTypes[1] : " + etherTypes[1] + " res: " + res);
		
		return res;
	}
	
	/*
	 * Based on libpcap/ethertype.h
	 */
	private static final int[] etherTypes = new int[] {
			0x0200,	/* ETHERTYPE_PUP 	- PUP protocol */
			0x0800,	/* ETHERTYPE_IP 	- IP protocol */
			0x0806,	/* ETHERTYPE_ARP 	- Addr. resolution protocol */
			0x8035,	/* ETHERTYPE_REVARP - reverse Addr. resolution protocol */
			0x0600, /* ETHERTYPE_NS			*/
			0x0500, /* ETHERTYPE_SPRITE		*/
			0x1000, /* ETHERTYPE_TRAIL  	*/
			0x6001, /* ETHERTYPE_MOPDL		*/
			0x6002, /* ETHERTYPE_MOPRC		*/
			0x6003, /* ETHERTYPE_DN 		*/
			0x6004, /* ETHERTYPE_LAT		*/
			0x6007, /* ETHERTYPE_SCA		*/
			0x8035, /* ETHERTYPE_REVARP		*/
			0x8038, /* ETHERTYPE_LANBRIDGE 	*/
			0x803c, /* ETHERTYPE_DECDNS		*/
			0x803e, /* ETHERTYPE_DECDTS		*/
			0x805b, /* ETHERTYPE_VEXP		*/
			0x805c, /* ETHERTYPE_VPROD		*/
			0x809b, /* ETHERTYPE_ATALK		*/
			0x80f3, /* ETHERTYPE_AARP		*/
			0x8100, /* ETHERTYPE_8021Q		*/
			0x8137, /* ETHERTYPE_IPX		*/
			0x86dd, /* ETHERTYPE_IPV6		*/
			0x8847, /* ETHERTYPE_MPLS		*/
			0x8848, /* ETHERTYPE_MPLS_MULTI */
			0x8863, /* ETHERTYPE_PPPOED		*/
			0x8864, /* ETHERTYPE_PPPOES		*/
			0x9000, /* ETHERTYPE_LOOPBACK	*/
			
	};
	private static final int[] ipProtos = new int[] {
			IP_PROTO_TCP,
			IP_PROTO_UDP
	};
}
