package pcap_packet_counter;

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

public class PacketRecordReader extends RecordReader<LongWritable, BytesWritable> {
	private static final Log LOG = LogFactory.getLog(RecordReader.class);

	private long start;
	private long pos;
	private long end;
	
	private LongWritable keyPacketOffset = null;
	private BytesWritable valuePacketBytes = null;
	
	FSDataInputStream fileIn = null;
	
	@Override
	public void close() 
			throws IOException {
		if (fileIn != null)
		{
			fileIn.close();
		}
	}

	@Override
	public LongWritable getCurrentKey() 
			throws IOException, InterruptedException {
		return keyPacketOffset;
	}

	@Override
	public BytesWritable getCurrentValue() 
			throws IOException, InterruptedException {
		return valuePacketBytes;
	}

	@Override
	public float getProgress() 
			throws IOException, InterruptedException {
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
			throws IOException, InterruptedException {
		
		FileSplit split = (FileSplit) genericSplit;
	    Configuration job = context.getConfiguration();
	    
	    start = split.getStart();
	    end = start + split.getLength();
	    final Path file = split.getPath();
	    
	    // open the file and seek to the start of the split
	    FileSystem fs = file.getFileSystem(job);
	    fileIn = fs.open(split.getPath());
	    
	    //seek to the start of the input split, skip pcap header
	    //start += PcapUtilities.PCAP_HEADER_SIZE;
	    fileIn.seek(start);
	    this.pos = start;
	}

	@Override
	public boolean nextKeyValue() 
			throws IOException, InterruptedException {
		if(pos >= end)
		{
			return false;
		}
		else
		{
			{//keyPacketOffset
				if (keyPacketOffset == null)
				{
					keyPacketOffset = new LongWritable();
				}
				
				keyPacketOffset.set(pos);
			}
			
			{//valuePacketBytes
				try 
				{
					int len = PcapUtilities.readPacketHeader(fileIn);
														
					if (valuePacketBytes == null)
					{
						valuePacketBytes = new BytesWritable();
					}
					
					//valuePacketBytes.setCapacity(len);
					//valuePacketBytes.setSize(len);
					
					byte[] payload = new byte[len];
					fileIn.read(payload, 0, len);
					valuePacketBytes.set(payload, 0, len);
					
					pos += PcapUtilities.PACKET_HEADER_SIZE + len;
				} 
				catch (PcapInputFormatException e) 
				{
					LOG.debug(e.getMessage());
					return false;
				}
			}
			
			return true;
		}
	}
}
