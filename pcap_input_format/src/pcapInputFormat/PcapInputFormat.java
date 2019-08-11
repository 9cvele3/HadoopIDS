package pcapInputFormat;

import pcap.*;

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

public class PcapInputFormat extends FileInputFormat<LongWritable, BytesWritable> 
{
	private static final Log LOG = LogFactory.getLog(FileInputFormat.class);

	private static final double SPLIT_SLOP = 1.1;   // 10% slop
	
	private static final int MB = 1024 * 1024;
	
	@Override
	public RecordReader<LongWritable, BytesWritable> createRecordReader(InputSplit arg0, TaskAttemptContext arg1)
			throws IOException, InterruptedException 
	{
		return new PacketRecordReader();
	}

	@Override
	public List<InputSplit> getSplits(JobContext job) 
			throws IOException 
	{

		long minSize = Math.max(getFormatMinSplitSize(), getMinSplitSize(job));
	    long maxSize = getMaxSplitSize(job);
	    LOG.info("maxSize InputSplit: " + maxSize);
	    final long limitForSpliting = 125 * 1024 * 1024;//128 MB

	    List<InputSplit> splits = new ArrayList<InputSplit>();
		
		for (FileStatus fileStatus: listStatus(job))
		{
		      Path path = fileStatus.getPath();
		      long length = fileStatus.getLen();
		      
		      System.out.println("Processing file: " + path + " length in bytes: " + length);
		      
		      if (
		    		  (length != 0) 						// not a zero length file
		    		  && (length > limitForSpliting)		// larger than 128MB (one block) 
		    	)
		      { 
		    	  long blockSize = fileStatus.getBlockSize();
		    	  long splitSize = computeSplitSize(blockSize, minSize, maxSize);
		
		    	  // deterministicBoundarySearch(splits, job, fileStatus, splitSize);
		    	  probabilisticBoundarySearch(splits, job, fileStatus, splitSize);
		      }
		      else if (length != 0) //if it is unsplitable
    		  {
		    	  LOG.info("PcapInputFormat: File is not splitable, adding the whole file as InputSplit!");
		    	  splits.add(getFileSplit(job, fileStatus, pcap.PcapUtils.PCAP_HEADER_SIZE, length - pcap.PcapUtils.PCAP_HEADER_SIZE));
    		  }
    		  else //if it is zero length file
    		  { 
    			  LOG.info("PcapInputFormat: File iz zero length, not creating an InputSplit!");
    		  }
		}//for
		
		LOG.info("PcapInputFormat. Total # of splits: " + splits.size());
		return splits;
	}

	private void deterministicBoundarySearch(List<InputSplit> splits, JobContext job, FileStatus fileStatus, long splitSize) 
			throws IOException {
		  LOG.info("Using deterministic boundary search!");
		
		  Path path 		= fileStatus.getPath();
		  FileSystem fs 	= path.getFileSystem(job.getConfiguration());
		  long length 		= fileStatus.getLen();
		  FSDataInputStream fileIn = fs.open(path);
		 
		  try
		  {//Process one pcap file
			  PcapUtils.checkPcapHeader(fileIn);
			  long bytesRead = pcap.PcapUtils.PCAP_HEADER_SIZE;

			  long bytesRemaining = length - pcap.PcapUtils.PCAP_HEADER_SIZE;
			  long startOfSplit = pcap.PcapUtils.PCAP_HEADER_SIZE;
			  
			  while ((double) bytesRemaining / splitSize > SPLIT_SLOP)
			  {
				  long splitCurrentSize = 0;
				  
				  while (splitCurrentSize < splitSize)
				  {
					  fileIn.seek(bytesRead);//absolute, not relative
					  
					  int packetLen = PcapUtils.readPacketHeader(fileIn);
					  //System.out.println(packetLen);
					  bytesRead += pcap.PcapUtils.PACKET_HEADER_SIZE + packetLen;
					  
					  splitCurrentSize += pcap.PcapUtils.PACKET_HEADER_SIZE + packetLen;
				  }
				  
				  splits.add(getFileSplit(job, fileStatus, startOfSplit, splitCurrentSize));
				  LOG.info("Added new InputSplit. Start offset: " + startOfSplit + " size in bytes: " + splitCurrentSize);
				  startOfSplit += splitCurrentSize;
				  bytesRemaining -= splitCurrentSize;
			  }

			  if (bytesRemaining != 0) 
			  {
				  LOG.info("Last chunk of file as separate InputSplit. Size in bytes: " + bytesRemaining);
				  splits.add(getFileSplit(job, fileStatus, length-bytesRemaining, bytesRemaining)); 
			  }
		  }//Process one pcap file - end
		  catch (PcapException e)//try to process other pcaps if this one is invalid 
		  {
			  LOG.error("PcapInputFormat: " + e.getMessage());
		  }

		  fileIn.close();
	}
	
	private void probabilisticBoundarySearch(List<InputSplit> splits, JobContext job, FileStatus fileStatus, long splitSize) 
			throws IOException {
		LOG.info("Using probabilistic boundary search!");
		
	    Path path 		= fileStatus.getPath();
	    FileSystem fs 	= path.getFileSystem(job.getConfiguration());
	    long length 	= fileStatus.getLen();
		FSDataInputStream fileIn = fs.open(path);

		  try
		  {//Process one pcap file
			  long searchChunkSize = 10 * MB;
			  long skipLen = splitSize - searchChunkSize;
			  PcapUtils.checkPcapHeader(fileIn);
			  
			  long bytesRead = PcapUtils.PCAP_HEADER_SIZE;
			  long startOfSplit = PcapUtils.PCAP_HEADER_SIZE; //Pcap Header is excluded from InputSplit
			  long bytesRemaining = length - bytesRead;
			  
			  byte[] tmp = new byte[(int)searchChunkSize];
	
			  while ((double) bytesRemaining / splitSize > SPLIT_SLOP)
			  {
				  bytesRead += skipLen;
				  fileIn.read(bytesRead, tmp, 0, (int)searchChunkSize);
				  long localOffset = PcapUtils.seekForBoundary(tmp);
				  long splitCurrentSize =  skipLen + localOffset;
				  System.out.println("localOffset: " + localOffset + " startOfSplit: " + startOfSplit + " splitCurrentSize: " + splitCurrentSize);
				  				  
				  splits.add(getFileSplit(job, fileStatus, startOfSplit, splitCurrentSize));
				  LOG.info("Added new InputSplit. Start offset: " + startOfSplit + " size in bytes: " + splitCurrentSize);
				  startOfSplit += splitCurrentSize;
				  bytesRead += localOffset; 
				  bytesRemaining -= splitCurrentSize;
			  }

			  if (bytesRemaining != 0) 
			  {
				  LOG.info("Last chunk of file as separate InputSplit. Size in bytes: " + bytesRemaining);
				  splits.add(getFileSplit(job, fileStatus, length-bytesRemaining, bytesRemaining)); 
			  }
		  }//Process one pcap file - end
		  catch (pcap.PcapException e)//try to process other pcaps if this one is invalid 
		  {
			  LOG.error("PcapInputFormat: " + e.getMessage());
		  }

		  fileIn.close();
	}

	private FileSplit getFileSplit(JobContext job, FileStatus fileStatus, long start, long length) throws IOException
	{
		Path path 		= fileStatus.getPath();
	    FileSystem fs 	= path.getFileSystem(job.getConfiguration());

		// int blkIndex = getBlockIndex(blkLocations, startOfSplit + splitCurrentSize);

	    ArrayList<String> hosts = new ArrayList<String>();
	    
	    for (BlockLocation blockLocation: fs.getFileBlockLocations(fileStatus, start, length))
	    	for (String host: blockLocation.getHosts())
	    		hosts.add(host);
	    
	    String[] hostArr = new String[hosts.size()];
	    hosts.toArray(hostArr);
	    
	    // String[] hostOldApproach = fs.getFileBlockLocations(fileStatus, start, length)[0].getHosts();
	    
	    return new FileSplit(path, start, length, hostArr);
	}
	
	public int convertToUnsignedInt(byte b)
	{
		return b < 0 ? (256 + b) : b;
	}	
}
