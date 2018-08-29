package ids;

import java.io.IOException;

import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Reducer;

public class IDSReducer extends Reducer<Text, LongWritable, Text, LongWritable> {

	public void reduce(Text key, Iterable<LongWritable> values, Context context) throws IOException, InterruptedException {
		long numOfOccurences = 0;
		
		for (LongWritable value : values) {
			numOfOccurences += value.get();
		}
		
		context.write(new Text(key), new LongWritable(numOfOccurences));
	}
}
