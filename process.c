#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "arpheader.h"





int group_if(char * argv[],struct allpacket * packet)
{
    if(ntohs(packet->type) == ETHERTYPE_ARP
           && ntohs(packet->opcode) == ARPOP_REPLY && packet->arp_sender_ip == inet_addr(argv[2]))
        return 1;
}

int process(char * argv[],pcap_t * handle)
{

    struct pcap_pkthdr* header;
    const u_char* packet;

    pcap_next_ex(handle, &header, &packet);
    struct allpacket * new_packet = (struct allpacket *) packet;
    struct allpacket * save_packt[argcs-2];




    switch(group_if(argv,new_packet)){
    case 1:
        printf("######zESTING ###### ::: %x \n",save_packt[0]->arp_sender_ip);
        infect(argv,handle,new_packet);             //감염함수 :: 성공
    }



    printf("search...\n");
}
