#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

#define ETHER_DHOST 0
#define ETHER_SHOST 1

char *ether_ntoa(struct ethheader *addr, int _op)
{
  static char buf[18];

  if (_op == ETHER_DHOST)
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
          addr->ether_dhost[0],
          addr->ether_dhost[1],
          addr->ether_dhost[2],
          addr->ether_dhost[3],
          addr->ether_dhost[4],
          addr->ether_dhost[5]);
  else if (_op == ETHER_SHOST)
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
          addr->ether_shost[5],
          addr->ether_shost[4],
          addr->ether_shost[3],
          addr->ether_shost[2],
          addr->ether_shost[1],
          addr->ether_shost[0]);
  else
    sprintf(buf, "Invalid operation");
  return buf;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

	  printf("Ethernet Src Mac	: %s\n", ether_ntoa(eth, ETHER_SHOST));
    printf("Ethernet Dst Mac	: %s\n", ether_ntoa(eth, ETHER_DHOST));

    printf("IP Src IP         : %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("IP Dst IP         : %s\n", inet_ntoa(ip->iph_destip));    

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            printf("   Src port: %d\n", ntohs(((struct tcpheader*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader)))->tcp_sport));
            printf("   Dst port: %d\n", ntohs(((struct tcpheader*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader)))->tcp_dport));
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


