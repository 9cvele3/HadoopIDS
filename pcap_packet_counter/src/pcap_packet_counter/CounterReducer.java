package pcap_packet_counter;

import java.io.IOException;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Reducer;

public class CounterReducer extends Reducer<Text, LongWritable, Text, LongWritable> 
{
	@Override
	public void reduce(Text key, Iterable<LongWritable> values, Context context) 
			throws IOException, InterruptedException 
	{
		long numOccur = 0;
		
		for(LongWritable value: values)
		{
			numOccur += value.get();
		}
		
		context.write(new Text("ALL"), new LongWritable(numOccur));
	}
}