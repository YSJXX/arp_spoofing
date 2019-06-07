#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#pragma once
#define ARPHEADER_H

#define PACKETSIZE sizeof(struct allpacket)

void broadcast(char* argv[],pcap_t *handle);

u_int8_t mymac[6];
char myip[40];
#pragma pack(push,1)
struct allpacket
{
    u_int8_t eth_dmac[6];
    u_int8_t eth_smac[6];
    u_short type;


    u_short hd_type;
    u_short protocol_type;
    u_char hd_size;
    u_char protocol_size;
    u_short opcode;
    u_int8_t arp_sender_mac[6];
    u_int32_t arp_sender_ip;
    u_int8_t arp_target_mac[6];
    u_int32_t arp_target_ip;

};

struct jsave
{
    u_int8_t save_smac[6];  //90:aa
    u_int32_t save_sip;     //123.105
    u_int8_t save_tmac[6];  //bc:fa
    u_int32_t save_tip;     //123.1
    u_int8_t gateway[6];    //ff:05
};

#pragma pack(pop)


#define ETHERTYPE_ARP   0x0806
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
