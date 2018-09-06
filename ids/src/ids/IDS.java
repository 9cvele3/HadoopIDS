package ids;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

import pcapInputFormat.PcapInputFormat;


public class IDS 
	extends Configured 
	implements Tool
{

	public static void main(String[] args) 
			throws Exception
	{
		if(args.length < 2) 
		{
			System.err.println("Usage: IDS -files cached-rules.txt <inputpath> <outputpath>");
			System.exit(-1);
		}
		
		int res = ToolRunner.run(new Configuration(), new IDS(), args);
		System.exit(res);
		/*
		try {
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
	}

	@Override
	public int run(String[] args) 
			throws Exception 
	{
		//Job job = Job.getInstance();
		Job job = Job.getInstance(getConf());
		job.setJarByClass(IDS.class);
		job.setJobName("IDS");
		
		System.out.println("Arguments " + args[0] + " " + args[1]);
		FileInputFormat.addInputPath(job, new Path(args[0]));
		FileOutputFormat.setOutputPath(job, new Path(args[1]));
		
		job.setMapperClass(IDSMapper.class);
		job.setCombinerClass(IDSReducer.class);
		job.setReducerClass(IDSReducer.class);
		
		job.setInputFormatClass(PcapInputFormat.class);
		job.setMapOutputKeyClass(Text.class);
		job.setMapOutputValueClass(LongWritable.class);
		
		job.setOutputKeyClass(Text.class);
		job.setOutputValueClass(LongWritable.class);
		
		return job.waitForCompletion(true) ? 0 : 1;
	}
}
