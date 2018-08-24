package pcap_packet_counter;

import java.io.IOException;

import org.apache.hadoop.io.*;
import org.apache.hadoop.mapreduce.Mapper;

public class CounterMapper extends Mapper<LongWritable, BytesWritable, Text, LongWritable> {

	private static LongWritable ONE = new LongWritable(1);
	
	@Override
	public void map(LongWritable key, BytesWritable value, Context context) 
			throws IOException, InterruptedException {
		context.write(new Text("ALL"), ONE);
	}
}
