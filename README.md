# HadoopIDS

Hadoop (1.2.1) based intrusion detection system that uses Myers algorithm for pattern matching. 

Usage: `bin/hadoop jar ids.jar -files cached-rules.txt <inputIDS> <outputIDS>`

File `cached-rules.txt` is Snort database preprocessed with snort_rules_parser app to be suitable for Myers algorithm.
Directory `<inputIDS>` is directory on HDSF where input .pcap files are placed. 
Directory `<outputIDS>` is directory that will be created on HDFS. It will contain textual file that lists detected malicious activities. 

Example output:
<sid>,<src_ip>:<src_port>,<dst_ip>:<dst_port>	<num_detected>

100000,172.16.121.1:any,172.16.121.150:443	1
2024217,192.168.116.138:any,192.168.116.149:any	31
2024217,192.168.116.138:any,192.168.116.172:any	16
2024217,192.168.116.149:any,192.168.116.138:any	31
2024217,192.168.116.149:any,192.168.116.143:any	31
2024217,192.168.116.149:any,192.168.116.172:any	48
2024218,192.168.116.138:any,192.168.116.149:any	2
2024218,192.168.116.143:any,192.168.116.149:any	9
2024218,192.168.116.149:any,192.168.116.138:any	3
2024218,192.168.116.172:any,192.168.116.138:any	1
2024218,192.168.116.172:any,192.168.116.149:any	6
2024220,192.168.116.138:any,192.168.116.149:any	3
2024220,192.168.116.138:any,192.168.116.172:any	1
2024220,192.168.116.149:any,192.168.116.138:any	2
2024220,192.168.116.149:any,192.168.116.143:any	9
2024220,192.168.116.149:any,192.168.116.172:any	6
491,192.168.1.1:21,192.168.1.33:any	159
491,192.168.75.132:21,192.168.75.1:any	41

## Work Organization
All the heavy work is done in map phase (network packet decoding, pattern matching). Reduce phase is responsible for grouping and counting detected attacks.

## PcapInputFormat 
Three different InputFormats for pcap files were implemented. 
* deterministicBoundarySearch: InputSplit size is approximately equal to HDFS block size, but boundary is found at exact packet boundary by traversing .pcap file packet by packet. This approach had worst performance. 
* probabilisticBoundarySearch: InputSplit size is approximately equal to HDFS block size, boundary is found at exact packet boundary, but this time with a probabilistic algorithm. 
* simpleBoundarySearch: InputSplit size is equal to HDFS block size. This approach gave best results, but packets that are on the boundaries of blocks are ignored during processing. 
