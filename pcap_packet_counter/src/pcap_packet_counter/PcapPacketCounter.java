package pcap_packet_counter;


import java.io.IOException;

import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;

import pcapInputFormat.PcapInputFormat;

public class PcapPacketCounter 
{
	public static void main(String[] args) 
	{
		if(args.length != 2) 
		{
			System.err.println("Usage: CreateFile <inputpath> <outputpath>");
			System.exit(-1);
		}
		
		try 
		{
			Job job = Job.getInstance();
			job.setJarByClass(PcapPacketCounter.class);
			job.setJobName("PcapPacketCounter");
			
			FileInputFormat.addInputPath(job, new Path(args[0]));
			FileOutputFormat.setOutputPath(job, new Path(args[1]));
			
			job.setMapperClass(CounterMapper.class);
			job.setReducerClass(CounterReducer.class);
			job.setNumReduceTasks(1);
			
			job.setInputFormatClass(PcapInputFormat.class);
			job.setMapOutputKeyClass(Text.class);
			job.setMapOutputValueClass(LongWritable.class);
			
			System.exit(job.waitForCompletion(true) ? 0 : 1);
		}
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		catch (ClassNotFoundException e) 
		{
			e.printStackTrace();
		}
		catch (InterruptedException e) 
		{
			e.printStackTrace();
		}
	}
}