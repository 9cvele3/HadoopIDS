package pcap_packet_counter;

import java.io.IOException;

import org.apache.hadoop.fs.FSDataInputStream;

public class PcapUtilities {

	public final static int PCAP_HEADER_SIZE = 24; //size in bytes
	public final static int PACKET_HEADER_SIZE = 16; //size in bytes
	public final static int PCAP_MAGIC_LITTLE_ENDIAN = 1;
	public final static int PCAP_MAGIC_BIG_ENDIAN = 1;
	public final static int DATA_LINK_TYPE_ETHERNET = 1;
	public final static int MAX_PACKET_LEN = 524288;

	interface Callback<T>
	{
		void callback(T param);
	}
	
	/**
	 * Converts big endian int to little endian int
	 * @param bigEndian - 32b int big endian value
	 * @return 32b int little endian value
	 */
	public static int ntoh(int bigEndian)
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
	public static boolean checkPcapHeader(FSDataInputStream fs, Callback<String> log) throws IOException
	{
		int magicNumber = fs.readInt();
		
		System.out.println("magic number: " + magicNumber);
		
		if (magicNumber != PCAP_MAGIC_LITTLE_ENDIAN && magicNumber != PCAP_MAGIC_BIG_ENDIAN)
		{
			log.callback("Pcap magic number is wrong!");
			return false;
		}
		
		byte[] unimportantBytes = new byte[16];
		int numBytesRead = fs.read(unimportantBytes, 0, 16);
		
		if (numBytesRead < 16)
		{
			log.callback("Pcap header is too short!");
			return false;
		}
		
		int network = fs.readInt();
		
		if(network != DATA_LINK_TYPE_ETHERNET)
		{
			log.callback("Only Ethernet is supported at this moment");
			return false;
		}
		
		return true;
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
		/*int ts_sec 	= */	fs.readInt();
		/*int ts_usec 	= */	fs.readInt();
		int incl_len 	=		ntoh(fs.readInt());
		/*int orig_len 	= */	fs.readInt();

		if (incl_len > MAX_PACKET_LEN)
		{
			throw new PcapInputFormatException("Packet len " + incl_len + " is larger than maximum packet len");
		}
		
		return incl_len;
	}
}
