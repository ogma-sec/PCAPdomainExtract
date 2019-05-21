#!/usr/bin/python
from scapy.all import *
import os 
import sys
import getopt 

def usage():
    """
    Display usage
    """
    usageText = "Python script used to extract DNS query and response from PCAP file.\n\n"
    usageText += "Find Last version : https://github.com/nj8/PCAPdomainExtract \n"
    usageText += "Author : Mickael Dorigny/nj8\n\n"
    usageText += " Usage : \n\t python PCAPdomainExtract.py -i <file.pcap> [OPTIONS]"
    usageText += " \n\n Options :\n"
    usageText += " \t -i : input PCAP file (mandatory)\n"
    usageText += " \t -a : Display response with DNS type A (IPv4) only \n"
    usageText += " \t -6 : Display response with DN?S type AAAA (IPv6) only \n"
    usageText += " \t -s : Hide DNS type SOA from response (avoid weird display)\n"
    usageText += " \t -e : Display al DNS type response except A\n"
    print usageText

myopts, args = getopt.getopt(sys.argv[1:], "i:ea6hs")

allExceptA = False
getAQuery = False
getAAAAQuery = False
hideSOA = False

if len(sys.argv) < 2:
    usage()
    exit(0)

for o, a in myopts:
    if o == "-i":
        inputFile = a
    if o == "-e":
        allExceptA = True
    if o == "-a":
        getAQuery = True
    if o == "-6":
        getAAAAQuery = True
    if o == "-s":
        hideSOA = True
    if o == "-h":
        usage()
        exit(0)
if allExceptA == True and getAQuery == True:
    print "Error : Option -e and -a cannot be used together"
    usage()
    exit(0)

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(inputFile)

rrTypeDic= {
	"1" : "[A]",
	"2" : "[NS]",
	"3" : "[MD]",
	"4" : "[MF]",
	"5" : "[CNAME]",
	"6" : "[SOA]",
	"7" : "[MB]",
	"8" : "[MG]",
	"9" : "[MR]",
	"10" : "[NULL]",
	"11" : "[WKS]",
	"12" : "[PTR]",
	"13" : "[HINFO]",
	"14" : "[MINFO]",
	"15" : "[MX]",
	"16" : "[TXT]",
	"17" : "[RP]",
	"18" : "[AFSDB]",
	"19" : "[X25]",
	"20" : "[ISDN]",
	"21" : "[RT]",
	"22" : "[NSAP]",
	"23" : "[NSAP-PTR] ",
	"24" : "[SIG]",
	"25" : "[KEY]",
	"26" : "[PX]",
	"27" : "[GPOS]",
	"28" : "[AAAA]",
	"29" : "[LOC]",
	"30" : "[NXT]",
	"31" : "[EID]",
	"32" : "[NIMLOC]",
	"33" : "[SRV]",
	"34" : "[ATMA]",
	"35" : "[NAPTR]",
	"36" : "[KX]",
	"37" : "[CERT]",
	"38" : "[A6]",
	"39" : "[DNAME]",
	"40" : "[SINK]",
	"41" : "[OPT]",
	"42" : "[APL]",
	"43" : "[DS]",
	"44" : "[SSHFP]",
	"45" : "[IPSECKEY]",
	"46" : "[RRSIG]",
	"47" : "[NSEC]",
	"48" : "[DNSKEY]",
	"49" : "[DHCID]",
	"50" : "[NSEC3]",
	"51" : "[NSEC3RAM]",
	"52" : "[TLSA]",
	"53" : "[SMIMEA]",
	"55" : "[HIP]",
	"56" : "[NINFO]",
	"57" : "[RKEY]",
	"58" : "[TALINK]",
	"59" : "[CDS]",
	"60" : "[CDNSKEY]",
	"61" : "[OPENPGPKEY]",
	"62" : "[CSYNC]",
	"99" : "[SPF]",
	"100" : "[UINFO]",
	"101" : "[UID]",
	"102" : "[GID]",
	"103" : "[UNSPEC]",
	"104" : "[NID]",
	"105" : "[L32]",
	"106" : "[L64]",
	"107" : "[LP]",
	"108" : "[EUI48]",
	"109" : "[EUI64]",
	"249" : "[TKEY]",
	"250" : "[TSIG]",
	"251" : "[IXFR]",
	"252" : "[AXFR]",
	"253" : "[MAILB]",
	"254" : "[MAILA]",
	"256" : "[URI]",
	"257" : "[CAA]",
	"258" : "[AVC]",
	"259" : "[DOA]",
	"32768" : "[TA]",
	"32769" : "[DL]"
	       
        }	

# list of all DNSQR
dnsqrList=[]

for packet in packets:
    if packet.haslayer(DNSQR):
        try :
            ipDst = packet[IP].dst
        except:
            ipDst = "Unknown"
        queryInfo = packet.getlayer(DNSQR)
        # print queryInfo.qname
        dnsqrList.append([queryInfo.qname,ipDst])

#my_set = set(dnsqrList)
#sortedDnsqrList = list(my_set)
sortedDnsqrList = dnsqrList
# Only get DNSRR
# dict of all DNSRR
dnsrrDict={}
for packet in packets:
   if packet.haslayer(DNSRR):
        responseInfo = packet.getlayer(DNSRR)
        try:
            recordType = rrTypeDic[str(responseInfo.type)]
        except:
            recordType = "UNKNOWN"+str(responseInfo.type)
            
        if (allExceptA == True and "[A]" not in recordType):
            if (hideSOA == True and "[SOA]" not in recordType):
                dnsrrDict[str(responseInfo.rrname)]=(recordType,str(responseInfo.rdata))
        if getAQuery and "[A]" in recordType:
            dnsrrDict[str(responseInfo.rrname)]=(recordType,str(responseInfo.rdata))
        if getAAAAQuery and "[AAAA]" in recordType:
            dnsrrDict[str(responseInfo.rrname)]=(recordType,str(responseInfo.rdata))
        if allExceptA == False and getAQuery == False and getAAAAQuery == False:
            if (hideSOA == True and "[SOA]" not in recordType):
               dnsrrDict[str(responseInfo.rrname)]=(recordType,str(responseInfo.rdata))
	    else:
	       dnsrrDict[str(responseInfo.rrname)]=(recordType,str(responseInfo.rdata))
   
# DNS QUERY 
print("\n##########  DNS QUERY ############\n")
print("{: >30}, {: >15}".format("DNS query","Server dest"))
print("{: >30}, {: >15}".format("------","------"))

for query in sortedDnsqrList:

    print("{: >30}, {: >15}".format(*query))

# DNS RESPONSE
print("\n##########  DNS RESPONSE #########\n")
print("{: >10}, {: >30}, {: >30}".format("DNS type","domain","response"))
print("{: >10}, {: >30}, {: >30}".format("------","------","------"))

for key,values in dnsrrDict.items():
    print("{: >10}, {: >30}, {:>30}".format(str(values[0]),str(key),str(values[1])))

# DNS QUERY WITHOUT RESPOSNE
print("\n### DNS QUERY WITHOUT RESPONSE ####")
print("[!] Also diplay response that are not in the specified\n    type (if option -e, -a or -6 are used).\n")

print("{: >30}, {: >15}".format("DNS query","Server dest"))
print("{: >30}, {: >15}".format("------","------"))
for query in sortedDnsqrList:
    if query[0] not in dnsrrDict:
        print("{: >30}, {: >15}".format(query[0], query[1]))
