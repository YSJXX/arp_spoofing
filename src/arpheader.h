#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <pthread.h>

#pragma once
#define ARPHEADER_H

#define PACKETSIZE sizeof(struct allpacket)

void broadcast(char *argv[], pcap_t *pcapHandle);
void gateway_mac(char *argv[], pcap_t *pcapHandle);
int check_mac(u_int8_t *mac1, u_int8_t *mac2);

u_int8_t mymac[6];
char myip[40];
#pragma pack(push, 1)
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
    u_int8_t save_smac[6]; // Sender mac
    u_int32_t save_sip;    // 공격 대상 IP
    u_int32_t save_tip;    // Gateway ip
    u_int8_t gateway[6];
};

#pragma pack(pop)

#define ETHERTYPE_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
