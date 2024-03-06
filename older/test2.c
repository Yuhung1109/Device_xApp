#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "common.h"

#define BUFFER_SIZE 1500

void process_gre_dhcp_packet(char *packet, ssize_t packet_len) {
    
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct in_addr src_addr = ip_header->ip_src;
    struct in_addr dst_addr = ip_header->ip_dst;
    char src_ip_addr[INET_ADDRSTRLEN];
    char dst_ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_addr, src_ip_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip_addr, INET_ADDRSTRLEN);
    printf("src IP: %s\n", src_ip_addr);
    printf("dst IP: %s\n", dst_ip_addr);

    packet += (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));

    packet_len -= (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct gre_header));
    printf("Received DHCP packet:\n");
    // for (ssize_t i = 0; i < dhcp_packet_len; ++i) {
    //     printf("%02X ", dhcp_packet[i]);
    // }
    // printf("\n");

    // ³z¹L sendto ±N DHCP «Ê¥]µo°e¨ì eno1:1
    int sockfd;
    struct sockaddr_in sa;

    // ³Ð«Ø¤@­Ó UDP Socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // ³]¸m¥Øªº¦a§}¬° eno1:1 ªº IP ©MºÝ¤f¡A½Ð®Ú¾Ú¹ê»Ú±¡ªp½Õ¾ã
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("192.168.1.1");
    sa.sin_port = htons(67);

    // µo°e DHCP «Ê¥]¨ì eno1:1
    ssize_t sent_len = sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_in));
    if (sent_len == -1) {
        perror("Error sending DHCP packet to eno1:1");
    } else {
        printf("Sent DHCP packet to eno1:1\n");
    }

    close(sockfd);
}

int main() {
    int sockfd;
    char buffer[BUFFER_SIZE];

    // ³Ð«Ø Raw Socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // ¸j©w¨ì eno1 ºô¥d
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("eno1");

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) == -1) {
        perror("Error binding socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        // ±µ¦¬«Ê¥]
        ssize_t packet_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (packet_len == -1) {
            perror("Error receiving packet");
            break;
        }

        // ³B²z GRE «Ê¸Ëªº DHCP «Ê¥]
        process_gre_dhcp_packet(buffer, packet_len);
    }

    // Ãö³¬ Socket
    close(sockfd);

    return 0;
}
