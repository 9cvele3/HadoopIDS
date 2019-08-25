bin/hdfs dfs -rm -f -r /textout
bin/yarn jar ./share/hadoop/mapreduce/hadoop-mapreduce-examples-2.9.0.jar wordcount /text /textout

