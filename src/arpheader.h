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
u_int8_t broadcast_mac[6];
u_int8_t mymac[6];
char *dev;
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
    u_int8_t save_target_mac[6];
    u_int32_t save_target_ip;
    u_int32_t save_gateway_ip;
    u_int8_t save_gateway_mac[6];
};

void sendBroadcast(char *argv[], pcap_t *pcap_handle, u_int8_t type);
int compareMac(u_int8_t *mac1, u_int8_t *mac2);
void insertPacketField(u_int8_t *pkt, char *argv[], u_int8_t type);
void insertInfectPacketField(u_int8_t *pkt, void *arg, char current);
void insertFixedField(u_int8_t *pkt, u_int8_t opcode);
int getMyMacIp(char *dev);

#pragma pack(pop)

#define ETHERTYPE_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPHEADER_H
#define TARGET 100
#define GATEWAY 101
#define PACKETSIZE sizeof(struct eth_arp_header)