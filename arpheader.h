#include <stdint.h>
#include <stdlib.h>

#pragma once
#define ARPHEADER_H

#define PACKETSIZE sizeof(struct allpacket)
#pragma pack(push,1)

int argcs;




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
#pragma pack(pop)


#define ETHERTYPE_ARP   0x0806
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
