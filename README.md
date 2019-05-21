# PCAPdomainExtract
Python script that extract all DNS query and response from a PCAP file

No requirement except Python

Usage : 
 
	 python PCAPdomainExtract.py -i <file.pcap> [OPTIONS] 
	 

Options :
 
-i : input PCAP file (mandatory)
	
-a : Display response with DNS type A (IPv4) only 
	 
-6 : Display response with DN?S type AAAA (IPv6) only 
	 
-s : Hide DNS type SOA from response (avoid weird display)
	 
-e : Display al DNS type response except A
