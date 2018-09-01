package pcapInputFormat;

import java.io.IOException;

import org.apache.hadoop.fs.FSDataInputStream;

public class PcapUtilities {

	public final static int PCAP_HEADER_SIZE = 24; //size in bytes
	public final static int PACKET_HEADER_SIZE = 16; //size in bytes
	public final static int PCAP_MAGIC_LITTLE_ENDIAN = 0xa1b2c3d4;
	public final static int PCAPNG_MAGIC_LITTLE_ENDIAN = 0x0a0d0d0a;
	//public final static int DATA_LINK_TYPE_ETHERNET = 1;
	public final static int MAX_PACKET_LEN = 524288;
	
	/**
	 * Converts big endian int to little endian int
	 * @param bigEndian - 32b int big endian value
	 * @return 32b int little endian value
	 */
	public static int ntohl(int bigEndian)
	{
		int littleEndian = 0;
		
		for(int i = 0; i < 4; i++)
		{
			littleEndian = littleEndian << 8;
			littleEndian |= (bigEndian & 0xff);
			bigEndian = bigEndian >> 8;
		}
		
		return littleEndian;
	}

	/**
	 * Converts big endian short to little endian short
	 * @param bigEndian - 16b short big endian value
	 * @return 16b short little endian value
	 */
	public static short ntohs(short bigEndian)
	{
		short littleEndian = 0;
		littleEndian |= (bigEndian & 0xff);
		littleEndian = (short) (littleEndian << 8);
		bigEndian = (short) (bigEndian >> 8);
		littleEndian |= (bigEndian & 0xff);
		return littleEndian;
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
	public static void checkPcapHeader(FSDataInputStream fs) throws IOException, PcapInputFormatException
	{
		int magicNumber = ntohl(fs.readInt());
			
		if (magicNumber != PCAP_MAGIC_LITTLE_ENDIAN )
		{
			if(magicNumber == PCAPNG_MAGIC_LITTLE_ENDIAN)
			{
				throw new PcapInputFormatException("This is pcapng file. Use pcap file instead.");
			}
			else
			{
				throw new PcapInputFormatException("Pcap magic number is wrong: " + magicNumber);
			}
		}
		
		byte[] unimportantBytes = new byte[16];
		int numBytesRead = fs.read(unimportantBytes, 0, 16);
		
		if (numBytesRead < 16)
		{
			throw new PcapInputFormatException("Pcap header is too short!");
		}
		
		/*
		int network = fs.readInt();
		 
		if(network != DATA_LINK_TYPE_ETHERNET)
		{
			throw new PcapInputFormatException("Only Ethernet is supported at this moment");
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
	public static int readPacketHeader(FSDataInputStream fs) throws IOException, PcapInputFormatException
	{
		/*int ts_sec 	=*/ 	fs.readInt();
		/*int ts_usec 	=*/		fs.readInt();
		int incl_len 	=		ntohl(fs.readInt());
		//int orig_len 	= 	fs.readInt();

		//System.out.println("ts_sec: " + ts_sec + " ts_usec: " + ts_usec + " incl_len: " + incl_len + " orig_len: " + orig_len);
		
		if (incl_len > MAX_PACKET_LEN)
		{
			throw new PcapInputFormatException("Packet len " + incl_len + " is larger than maximum packet len");
		}
		
		if(incl_len == 0)
		{
			throw new PcapInputFormatException("Packet len is 0");
		}
		
		return incl_len;
	}
}
