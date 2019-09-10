package pcapInputFormat;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.*;
import java.io.IOException;

import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;

import pcap.*;

public class PacketRecordReader extends RecordReader<LongWritable, BytesWritable> 
{
	private static final Log LOG = LogFactory.getLog(RecordReader.class);

	private long start;
	private long pos;
	private long end;
	
	private LongWritable keyPacketOffset = new LongWritable();
	private BytesWritable valuePacketBytes = new BytesWritable();
	private byte[] tmpBytes = new byte[PcapUtils.MAX_PACKET_LEN];
	
	FSDataInputStream fileIn = null;
	int numPackets = 0;
	
	@Override
	public void close() 
			throws IOException 
	{
		if (fileIn != null)
		{
			fileIn.close();
		}
	}

	@Override
	public LongWritable getCurrentKey() 
			throws IOException, InterruptedException 
	{
		return keyPacketOffset;
	}

	@Override
	public BytesWritable getCurrentValue() 
			throws IOException, InterruptedException 
	{
		return valuePacketBytes;
	}

	@Override
	public float getProgress() 
			throws IOException, InterruptedException 
	{
	    if (start == end) 
	    {
	    	LOG.warn("start == end == " + start);
	        return 0.0f;
	    } 
	    else
	    {
	        return Math.min(1.0f, (pos - start) / (float)(end - start));
	    }
	}

	@Override
	public void initialize(InputSplit genericSplit, TaskAttemptContext context) 
			throws IOException, InterruptedException 
	{
		FileSplit split = (FileSplit) genericSplit;
	    Configuration job = context.getConfiguration();
	    
	    start = split.getStart();
	    end = start + split.getLength();
	    LOG.info("Split start: " + start + " Split end: " + end + " Split len: "  + split.getLength());
	    final Path file = split.getPath();
	    
	    // open the file and seek to the start of the split
	    FileSystem fs = file.getFileSystem(job);
	    fileIn = fs.open(split.getPath());
	    
	    valuePacketBytes.setCapacity(PcapUtils.MAX_PACKET_LEN);
	    this.pos = start;
	    
	    this.numPackets = 0;
	}
	
	@Override
	public boolean nextKeyValue() 
			throws IOException, InterruptedException 
	{
		if (pos == start)
		{
			LOG.info("Initial seek to start of InputSplit " + start);
			
			fileIn.seek(start);
			fileIn.read(tmpBytes, 0, PcapUtils.MAX_PACKET_LEN);
			
			try {
				pos = start + PcapUtils.seekForBoundary(tmpBytes);
				
				if (pos >= end)
				{
					LOG.error("Valid start not found!");
					return false;
				}
				else
				{
					fileIn.seek(pos);
					LOG.info("PacketRecordReader found valid start " + pos);
				}
			} catch (PcapException e) {
				LOG.error("PacketRecordReader valid start is not found!");
				e.printStackTrace();
			}
		}
		
		if (pos >= end)
		{
			LOG.warn("pos >= end " + pos + " " + end);
			return false;
		}
		else
		{
			keyPacketOffset.set(pos);
			
			try 
			{
				if (pos != fileIn.getPos())
				{
					LOG.warn("Need to seek!");
					fileIn.seek(pos);
				}

				int len = PcapUtils.readPacketHeader(fileIn, false);

				pos += PcapUtils.PACKET_HEADER_SIZE;

				if (pos + len > end) // it is not >= here
				{
					LOG.warn("pos + len > end");
					return false;
				}

				int bytesRead = fileIn.read(tmpBytes, 0, len);

				// both Capacity and Size are needed, otherwise different size for byte[] tmp = valuePacketBytes.getBytes()
				// Change the capacity of the backing storage.

				// Change the size of the buffer.
				valuePacketBytes.setSize(len);

				// Set the value to a copy of the given byte range
				valuePacketBytes.set(tmpBytes, 0, len);

				if(valuePacketBytes.getLength() != len)
				{
					LOG.error("Length does not match!");
				}
				else
				{
					// LOG.info("Packet " + this.numPackets + " at offset pos " + pos + " and with lenght len " + len);
					this.numPackets++;
				}

				pos += len;
			} 
			catch (PcapException e) 
			{
				LOG.error("PcapRecordReader exception at offset: " + fileIn.getPos() + e.getMessage());
				return false;
			}

			return true;
		}
	}
}
