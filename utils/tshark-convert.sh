INPUT_PCAP=inputPcap/idstrafficpcap.pcap
OUTPUT_TXT=tshark-output.txt

time tshark -r $INPUT_PCAP -C DisabledAppLevel -T fields -E separator=, -e ip.addr -e _ws.col.Protocol -e tcp.port -e udp.port -e data > $OUTPUT_TXT
