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
	
	private LongWritable keyPacketOffset = null;
	private BytesWritable valuePacketBytes = null;
	
	FSDataInputStream fileIn = null;
	
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
	    System.out.println("Split start: " + start + " Split end: " + end + " Split len: "  + split.getLength());
	    final Path file = split.getPath();
	    
	    // open the file and seek to the start of the split
	    FileSystem fs = file.getFileSystem(job);
	    fileIn = fs.open(split.getPath());
	    
	    this.pos = start;
	}

	@Override
	public boolean nextKeyValue() 
			throws IOException, InterruptedException 
	{
		if (pos == start)
		{
			byte[] searchStart = new byte[PcapUtils.MAX_PACKET_LEN];
			fileIn.seek(start);
			fileIn.read(searchStart, 0, PcapUtils.MAX_PACKET_LEN);
			
			try {
				pos = start + PcapUtils.seekForBoundary(searchStart);
				LOG.info("PacketRecordReader found valid start " + pos);
			} catch (PcapException e) {
				LOG.error("PacketRecordReader valid start is not found!");
				e.printStackTrace();
			}
		}
		
		if (pos >= end)
		{
			return false;
		}
		else
		{
			fileIn.seek(pos);
			
			{// keyPacketOffset
				keyPacketOffset = new LongWritable(pos);
			}
			
			{// valuePacketBytes
				try 
				{
					int len = PcapUtils.readPacketHeader(fileIn, false);

					pos += PcapUtils.PACKET_HEADER_SIZE;
					
					if (pos + len > end) // it is not >= here
						return false; 
					
					fileIn.seek(pos);
					// System.out.println("PackerRecordReader len: " + len);
					
					valuePacketBytes = new BytesWritable();
					
					// valuePacketBytes.setCapacity(len);
					// valuePacketBytes.setSize(len);
					byte[] payload = new byte[len];
					fileIn.read(payload, 0, len);
				
					// both are needed, otherwise different size for byte[] tmp = valuePacketBytes.getBytes()
					valuePacketBytes.setCapacity(len); 
					valuePacketBytes.setSize(len);
					
					valuePacketBytes.set(payload, 0, len);
					
					if(valuePacketBytes.getLength() != len)
					{
						LOG.error("Length does not match!");
					}
					
					pos += len;
				} 
				catch (PcapException e) 
				{
					LOG.error("PcapRecordReader: " + e.getMessage());
					return false;
				}
			}
			
			return true;
		}
	}
}
