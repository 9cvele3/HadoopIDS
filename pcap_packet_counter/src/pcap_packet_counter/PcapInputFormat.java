package pcap_packet_counter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.JobContext;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;

public class PcapInputFormat extends FileInputFormat<LongWritable, BytesWritable> {
	private static final Log LOG = LogFactory.getLog(FileInputFormat.class);

	private static final double SPLIT_SLOP = 1.1;   // 10% slop
	
	@Override
	public RecordReader<LongWritable, BytesWritable> createRecordReader(InputSplit arg0, TaskAttemptContext arg1)
			throws IOException, InterruptedException {
		return new PacketRecordReader();
	}

	@Override
	public List<InputSplit> getSplits(JobContext job) 
			throws IOException {

		long minSize = Math.max(getFormatMinSplitSize(), getMinSplitSize(job));
	    long maxSize = getMaxSplitSize(job);
	    LOG.info("maxSize InputSplit: " + maxSize);
	    final long limitForSpliting = 128 * 1024 * 1024;//128 MB

	    List<InputSplit> splits = new ArrayList<InputSplit>();
		
		for (FileStatus file: listStatus(job))
		{
		      Path path = file.getPath();
		      FileSystem fs = path.getFileSystem(job.getConfiguration());
		      long length = file.getLen();
		      BlockLocation[] blkLocations = fs.getFileBlockLocations(file, 0, length);
		      
		      if (
		    		  (length != 0) 						// not a zero length file
		    		  && (length > limitForSpliting)		// larger than 128MB (one block) 
		    	)
		      { 
		    	  long blockSize = file.getBlockSize();
		    	  long splitSize = computeSplitSize(blockSize, minSize, maxSize);
		
		    	  FSDataInputStream fileIn = fs.open(path);

		    	  try
		    	  {//Process one pcap file
			    	  PcapUtilities.checkPcapHeader(fileIn, message -> { LOG.debug(message); } );
	
			    	  long bytesRemaining = length;
			    	  long startOfSplit = PcapUtilities.PCAP_HEADER_SIZE;
			    	  
			    	  while ((double) bytesRemaining / splitSize > SPLIT_SLOP)
			    	  {
			    		  long splitCurrentSize = 0;
			    		  
			    		  while (splitCurrentSize < splitSize)
			    		  {
			    			  int packetLen = PcapUtilities.readPacketHeader(fileIn);
			    			  fileIn.seek(packetLen);
			    			  splitCurrentSize += PcapUtilities.PACKET_HEADER_SIZE + packetLen;
			    		  }
			    		  
			    		  int blkIndex = getBlockIndex(blkLocations, startOfSplit + splitCurrentSize);
			    		  splits.add(new FileSplit(path, startOfSplit, splitCurrentSize, blkLocations[blkIndex].getHosts()));
			    		  startOfSplit += splitCurrentSize;
			    		  bytesRemaining -= splitCurrentSize;
			    	  }

		    		  if (bytesRemaining != 0) 
			    	  {
			    		  splits.add(new FileSplit(path, length-bytesRemaining, bytesRemaining, 
			                     blkLocations[blkLocations.length-1].getHosts()));
			    	  }
		    	  }//Process one pcap file - end
		    	  catch (PcapInputFormatException e)//try to process other pcaps if this one is invalid 
		    	  {
		    		  LOG.debug(e.getMessage());
		    	  }

		    	  fileIn.close();
		      }
		      else if (length != 0) //if it is unsplitable
    		  {
    			  splits.add(new FileSplit(path, PcapUtilities.PCAP_HEADER_SIZE, length - PcapUtilities.PCAP_HEADER_SIZE, blkLocations[0].getHosts()));
    		  }
    		  else //if it is zero length file
    		  { 
    			  //Create empty hosts array for zero length files
    			  splits.add(new FileSplit(path, 0, length, new String[0]));
    		  }

		}//for
		
		LOG.debug("Total # of splits: " + splits.size());
		return splits;
	}
	
}
