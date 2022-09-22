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

#define PACKETSIZE sizeof(struct eth_arp_header)

void sendBroadcast(char *argv[], pcap_t *pcap_handle);
void getGatewayMac(char *argv[], pcap_t *pcap_handle);
int compareMac(u_int8_t *mac1, u_int8_t *mac2);

u_int8_t mymac[6];
char myip[40];
#pragma pack(push, 1)
struct eth_arp_header
{
    u_int8_t eth_dst_mac[6];
    u_int8_t eth_src_mac[6];
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

struct infect_addr_save
{
    u_int8_t save_target_mac[6]; // Sender mac
    u_int32_t save_target_ip;    // 공격 대상 IP
    u_int32_t save_gateway_ip;   // Gateway ip
    u_int8_t save_gateway_mac[6];
};

#pragma pack(pop)

#define ETHERTYPE_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
