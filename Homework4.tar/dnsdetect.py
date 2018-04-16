import logging
from scapy.all import *
import sys
from collections import deque

packetinpcap = deque(maxlen = 10)

def detect(pkt):
    if pkt.haslayer(DNSRR):
        if len(packetinpcap)>0:
            for original in packetinpcap:
                if original[IP].dst == pkt[IP].dst and original.src != pkt.src and original[IP].sport == pkt[IP].sport and original[IP].dport == pkt[IP].dport and\
                original[DNSRR].rdata != pkt[DNSRR].rdata and original[DNS].id == pkt[DNS].id and original[DNS].qd == pkt[DNS].qd and\
                original[DNS].qd.qname == pkt[DNS].qd.qname and original[IP].payload != pkt[IP].payload:
                    print "DNS spoofing detected:"
                    print "TXID: %s "%( original[DNS].id)
		    print "Request URL %s,SRC:%s,DST:%s"%(original[DNS].qd.qname,original[IP].src,original[IP].dst)
		    
                    print "1st response received:%s"%original[DNSRR].rdata
                    print "2nd response received:%s"%pkt[DNSRR].rdata
		    print "1st packet:",original.show()
		    print "2nd packet:s",pkt.show()
		    
		    
        packetinpcap.append(pkt)


if __name__ == '__main__':
    input = sys.argv
    global interface
    global tfile
    expression = None
    flagi=0
    flagf=0	
    try:
        for c in range(0,len(input)-1):
            if '-i' in input[c]:
	   	    interface= sys.argv[c+1]
            	    print "Interface to trace:",interface
            	    flagi =1
            if '-r' in input[c]:
                    tfile = sys.argv[c+1]
            	    print "TraceFile:",tfile
		    flagf =1
        if len(input)%2 == 0:
	    expression = sys.argv[len(input)-1]
            print "Expression:",expression
	if flagi==1 and flagf==1:
	   printf("enter either interface or file to trace , not both")   
           sys.exit()		 
        elif flagi==1:
            sniff(filter=expression, iface=interface, store=0, prn=detect,count=0)
	elif flagf==1:
	    sniff(filter=expression, offline = tfile, store=0, prn=detect)
        else:
	    print "Capture all interfaces"
            sniff(filter=expression, store=0, prn=detect,count=0)
            
    except AttributeError:
        print "Invalid entry/entries"
	print "Consider a single string in expression"
	print "dnsinject [-i interface] [-r tracefile] expression"


