package pcap;

import java.io.DataInputStream;
import java.io.IOException;

import utils.Utils;

public final class PcapUtils {
	public final static int MAC_ADDRESS_LEN_IN_BYTES = 6;
	public final static int ETHER_TYPE_IP = 0x0800;
	public final static int IP_PROTO_TCP = 0x06;
	public final static int IP_PROTO_UDP = 0x11;
	
	public final static int PCAP_HEADER_SIZE = 24; //size in bytes
	public final static int PACKET_HEADER_SIZE = 16; //size in bytes
	public final static int PCAP_MAGIC_LITTLE_ENDIAN = 0xa1b2c3d4;
	public final static int PCAPNG_MAGIC_LITTLE_ENDIAN = 0x0a0d0d0a;
	//public final static int DATA_LINK_TYPE_ETHERNET = 1;
	public final static int MAX_PACKET_LEN = 524288;
	public final static int MIN_PACKET_LEN = 48;
	
	public static long seekForBoundary(byte[] arr) throws PcapException
	{	
		for (int offset = 0; offset <= PcapUtils.MAX_PACKET_LEN; offset++)
		{
			if (seek(arr, offset))
				return offset;
		}
		
		throw new PcapException("Boundary was not found!");
	}
	
	/*
	 * Returns true if packet boundary is at offset, false otherwise.
	 */
	private static boolean seek(byte[] arr, int offset)
	{
		//System.out.println("\nSeek at offset : " + offset);
		int tollerance = 15;
		int numFound = 0;
		
		WholePcapPacketInfo curr = null;
		
		do
		{
			curr = WholePcapPacketInfo.decode(arr, offset);
			
			if (curr != null)
			{
				numFound++;
				offset += curr.len + PACKET_HEADER_SIZE;
			}
			
		} while(curr != null && offset < arr.length && numFound < tollerance);
				
		//System.out.println("Seek end");
		
		return numFound == tollerance;
	}
	
	/*
	typedef struct pcap_hdr_s {
        guint32 magic_number;   // magic number 
        guint16 version_major;  // major version numbers
        guint16 version_minor;  // minor version number
        gint32  thiszone;       // GMT to local correction
        guint32 sigfigs;        // accuracy of timestamps
        guint32 snaplen;        // max length of captured packets, in octets
        guint32 network;        // data link type
	} pcap_hdr_t;
	 */
	public static void checkPcapHeader(DataInputStream fs) 
			throws IOException, PcapException
	{
		int magicNumber = Utils.ntohl(fs.readInt());
			
		if (magicNumber != pcap.PcapUtils.PCAP_MAGIC_LITTLE_ENDIAN )
		{
			if(magicNumber == pcap.PcapUtils.PCAPNG_MAGIC_LITTLE_ENDIAN)
			{
				throw new PcapException("This is pcapng file. Use pcap file instead.");
			}
			else
			{
				throw new PcapException("Pcap magic number is wrong: " + magicNumber);
			}
		}
		
		byte[] unimportantBytes = new byte[16];
		int numBytesRead = fs.read(unimportantBytes, 0, 16);
		
		if (numBytesRead < 16)
		{
			throw new PcapException("Pcap header is too short!");
		}
		
		/*
		int network = fs.readInt();
		 
		if(network != DATA_LINK_TYPE_ETHERNET)
		{
			throw new PcapException("Only Ethernet is supported at this moment");
		}
		*/
	}

	/*
	typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         // timestamp seconds
        guint32 ts_usec;        // timestamp microseconds
        guint32 incl_len;       // number of octets of packet saved in file
        guint32 orig_len;       // actual length of packet
	} pcaprec_hdr_t;
	*/
	public static int readPacketHeader(DataInputStream fs) 
			throws IOException, PcapException
	{
		/*int ts_sec 	=*/ 	fs.readInt();
		/*int ts_usec 	=*/		fs.readInt();
		int incl_len 	=		Utils.ntohl(fs.readInt());
		//int orig_len 	= 	fs.readInt();

		//System.out.println("ts_sec: " + ts_sec + " ts_usec: " + ts_usec + " incl_len: " + incl_len + " orig_len: " + orig_len);
		System.out.println("incl_len: " + incl_len);
		
		if (incl_len > PcapUtils.MAX_PACKET_LEN)
		{
			throw new PcapException("Packet len " + incl_len + " is larger than maximum packet len");
		}
		
		if(incl_len == 0)
		{
			throw new PcapException("Packet len is 0");
		}
		
		return incl_len;
	}
	
/*
	public static boolean checkEtherType(int etherType, int len)
	{
		if (etherType < 1500)
			return len == (MAC_ADDRESS_LEN_IN_BYTES * 2 + 2 + etherType + 4);
		else
			return checkEtherType(etherType);
	}
*/
	
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
