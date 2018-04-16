#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<sys/time.h>
#include <netinet/if_ether.h>
typedef char * string;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
	int size_payload;
	const char *filter_exp=NULL;	/* The filter expression */	
	// some code from sniffer.c
	void print_hex_ascii_line(const u_char *payload, int len, int offset)
	{

		int i;
		int gap;
		const u_char *ch;

		/* hex */
		ch = payload;
		for(i = 0; i < len; i++) {
			printf("%02x ", *ch);
			ch++;
			
		}
	
		/* fill hex gap with spaces if not full line */
		if (len < 16) {
			gap = 16 - len;
			for (i = 0; i < gap; i++) {
				printf("   ");
			}
		}
		printf("   ");
	
		/* ascii (if printable) */
		ch = payload;
		for(i = 0; i < len; i++) {
			if (isprint(*ch))
				printf("%c", *ch);
			else
				printf(".");
			ch++;
		}

		printf("\n");

	return;
	}

	/*
	 * print packet payload data (avoid printing binary data)
	 */
	void print_payload(const u_char *payload, int len)
	{

		int len_rem = len;
		int line_width = 16;			/* number of bytes per line */
		int line_len;
		int offset = 0;					/* zero-based offset counter */
		const u_char *ch = payload;

		if (len <= 0)
			return;

		/* data fits on one line */
		if (len <= line_width) {
			print_hex_ascii_line(ch, len, offset);
			return;
		}

		/* data spans multiple lines */
		for ( ;; ) {
			/* compute current line length */
			line_len = line_width % len_rem;
			/* print line */
			print_hex_ascii_line(ch, line_len, offset);
			/* compute total remaining */
			len_rem = len_rem - line_len;
			/* shift pointer to remaining bytes to print */
			ch = ch + line_len;
			/* add offset */
			offset = offset + line_width;
			/* check if we have line width chars or less */
			if (len_rem <= line_width) {
				/* print last line and get out */
				print_hex_ascii_line(ch, len_rem, offset);
				break;
			}
		}

	return;
	}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
			
			int i=0;
			u_char *ptr;
			struct ether_header *eptr;
			eptr = (struct ether_header *) packet;
				
			/*Print source host address*/
		    ptr = eptr->ether_shost;
		    i = ETHER_ADDR_LEN;
		    do{
		        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
		    }while(--i>0);
		    printf(" -> ");
			
			/*Print destination host address*/
			ptr = eptr->ether_dhost;
		    i = ETHER_ADDR_LEN;
		    do{
		        printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
		    }while(--i>0);
			
		/* Do a couple of checks to see what packet type we have..*/
		    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
		    {
		        printf(" type 0x%x ",
		                ntohs(eptr->ether_type));
		    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
		    {
		        printf(" type 0x%x ",
		                ntohs(eptr->ether_type));
		    }else {
		        printf("type %x not IP", ntohs(eptr->ether_type));
		        exit(1);
		    }
			
			//print packet length
			printf("len %d",packet_header.len);
			
			
			/* print source and destination IP addresses */
			printf("\n%s ->", inet_ntoa(ip->ip_src));
			printf(" %s ", inet_ntoa(ip->ip_dst));
			
		/* determine protocol */	
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					printf("TCP\n");
					break;
				case IPPROTO_UDP:
					printf("UDP\n");
					return;
				case IPPROTO_ICMP:
					printf("ICMP\n");
					return;
				case IPPROTO_IGMP:
					printf("IGMP\n");
					return;
				case IPPROTO_IP:
					printf("IP\n");
					return;
				default:
					printf("unknown\n");
					return;
			}
			
			//print payload
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
				/*
				 * Print payload data; it might be binary, so don't just
				 * treat it as a string.
				 */
				if (size_payload > 0) {
					print_payload(payload, size_payload);
				}
		    
			}
void my_callback(u_char *useless,const struct pcap_pkthdr *pkthdr,const u_char*
        packet){
			char *dt= ctime((const time_t*)&pkthdr->ts.tv_sec);
			string month[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
			int i;
			char buffer[80];
				
			/* define ethernet header */
			ethernet = (struct sniff_ethernet*)(packet);
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			/* define/compute ip header offset */
			size_ip = IP_HL(ip)*4;
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			char *ret="r";
			if(filter_exp != NULL){
			ret = strstr((char *)payload,filter_exp);
			printf("%s",ret);
			}
			if (ret != NULL)
			{
				/*print date and time*/
			
			strftime(buffer,80,"%Y-%m-%d %H:%M:%S", localtime((const time_t*)&pkthdr->ts.tv_sec));
			printf("%s.%06d ",buffer,pkthdr->ts.tv_usec);
			print_packet_info(packet, *pkthdr);
			}
		 return;
			}
	int main(int argc, char *argv[])
	{
		 char *dev;
		 pcap_t *handle;	;
		 char errbuf[PCAP_ERRBUF_SIZE];
		 bpf_u_int32 mask;	
		 bpf_u_int32 net;
		 struct bpf_program fp;		/* The compiled filter expression */
		 char *expr;				/* The filter expression */
		 struct pcap_pkthdr header;	/* The header that pcap gives us */
		 const u_char *packet;		/* The actual packet */
		 int i;
		 i=0;
		 char *interface = "-i";
		 
		 char *r ="-r";
		 char *s ="-s";
		 //to store the filter expression 
		 if(argc%2 == 0){ 
			/* if(strcmp(argv[argc-3],s)||strcmp(argv[argc-3],r)||strcmp(argv[argc-3],interface) )
				 expr="";
			 else */
			 	expr=argv[argc-1];}
		 else{
			 expr="";
		 }
		 int count = 0;
		 //to store interface
		 while (argc != 0){
			if(strcmp(argv[i],interface)==0){
			 	dev = argv[i+1];
				handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
				count ++;
				
			}
			
			//to store file to read
		 	if(strcmp(argv[i],r)==0){
		 	   handle = pcap_open_offline(argv[i+1], errbuf);
			   count ++;
			  
	 	 	}
			
		 	if(strcmp(argv[i],s)==0){
		 	   filter_exp=argv[i+1];
			   
	 	 	}
			 i++;
			 argc--;
		 }
		 
		 // T o check if both -i and -r are present in command 
		 if (count == 2){
			 printf("Error:invalid command, both -i and -r cannot be present");
		 }
	 	if (handle == NULL )
	 		{
	 		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
	 		exit(1);
	 		}
		 
		 if( dev!= NULL){
		 	
		 
		 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 		 net = 0;
		 		 mask = 0;
		 	 }
			 
		 }
		 
		 if (handle == NULL) {
		 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 	return(2);
		 	 }
			 
		 if (pcap_datalink(handle) != DLT_EN10MB) {
			 fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
			 return(2);
			 }
			if(expr != NULL) {
		 if (pcap_compile(handle, &fp, expr, 0, net) == -1) {
			 fprintf(stderr, "Couldn't parse filter %s: %s\n", expr, pcap_geterr(handle));
			 return(2);
			 }
			 
		 if (pcap_setfilter(handle, &fp) == -1) {
			 fprintf(stderr, "Couldn't install filter %s: %s\n", expr, pcap_geterr(handle));
			 return(2);
			 	 }
			 }
	 /* Grab a packet */
			 
	 		/* Print its length */
	 		/*printf("Jacked a packet with length of [%d]\n", header.len);*/
			 if ( handle!= NULL && count==1){
			 pcap_loop(handle,-1,my_callback,NULL);
			 
		 }
			 
	 		/* And close the session */
	 		pcap_close(handle);
			
		 return(0);
	}
