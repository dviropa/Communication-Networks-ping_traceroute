#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <poll.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

#define PACKETSIZE	64
#define COUNT  4

// משתנים גלובליים לסטטיסטיקות
int packets_sent = 0;    // סך כל החבילות שנשלחו
int packets_received = 0; // סך כל החבילות שהתקבלו
double total_rtt = 0.0;  // RTT כולל
double min_rtt = -1.0, max_rtt = 0.0; // RTT מינימום ומקסימום
time_t start_time, end_time; // זמן התחלת וסיום התוכנית


struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

struct packet_ipv6 {
    struct icmp6_hdr hdr;
    char msg[PACKETSIZE - sizeof(struct icmp6_hdr)];
    uint16_t id;       // Identifier
    uint16_t sequence; // Sequence Number
};


void print_ipv4_packet_details(struct packet *pckt) {
    printf("Packet Details (IPv4):\n");

    printf("  ICMP Header:\n");
    printf("    Type: %d\n", pckt->hdr.type);
    printf("    Code: %d\n", pckt->hdr.code);
    printf("    Checksum: 0x%x\n", pckt->hdr.checksum);
    printf("    ID: %d\n", ntohs(pckt->hdr.un.echo.id));
    printf("    Sequence: %d\n", ntohs(pckt->hdr.un.echo.sequence));

    printf("  Message: %s\n", pckt->msg);
}

void print_ipv6_packet_details(struct packet_ipv6 *pckt) {

    printf("Packet Details (IPv6):\n");
    printf("  ICMP Header:\n");
    printf("  Type: %d\n", pckt->hdr.icmp6_type);
    printf("  Code: %d\n", pckt->hdr.icmp6_code);
    printf("  Checksum: 0x%x\n", pckt->hdr.icmp6_cksum);
    printf("  Message: %s\n", pckt->msg);
    printf("  ID: %d\n", ntohs(pckt->hdr.icmp6_dataun.icmp6_un_data16[0]));
    printf("  Sequence: %d\n", ntohs(pckt->hdr.icmp6_dataun.icmp6_un_data16[1]));

}


unsigned short int checksum(void *data, unsigned int bytes) {
    unsigned short int *data_pointer = (unsigned short int *)data;
    unsigned int total_sum = 0;

    // Main summing loop.
    while (bytes > 1)
    {
        total_sum += *data_pointer++; // Some magic pointer arithmetic.
        bytes -= 2;
    }

    // Add left-over byte, if any.
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);

    // Fold 32-bit sum to 16 bits.
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);

    // Return the one's complement of the result.
    return (~((unsigned short int)total_sum));
}

uint16_t calculate_icmp6_checksum(struct sockaddr *src, struct sockaddr *dest, void *icmp_pkt, size_t pkt_len) {
    struct {
        struct in6_addr src;
        struct in6_addr dest;
        uint32_t length;
        uint8_t zeros[3];
        uint8_t next_header;
    } pseudo_header;

    // Verify that the addresses are IPv6
    struct sockaddr_in6 *src_in6 = (struct sockaddr_in6 *)src;
    struct sockaddr_in6 *dest_in6 = (struct sockaddr_in6 *)dest;

    memset(&pseudo_header, 0, sizeof(pseudo_header));
    pseudo_header.src = src_in6->sin6_addr;
    pseudo_header.dest = dest_in6->sin6_addr;
    pseudo_header.length = htonl(pkt_len);
    pseudo_header.next_header = IPPROTO_ICMPV6;

    uint32_t sum = 0;


    // Calculate the checksum
    sum += checksum(&pseudo_header, sizeof(pseudo_header));
    sum += checksum(icmp_pkt, pkt_len);

    // Handle overflow
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}


double calculate_rtt(struct timeval start, struct timeval end) {
    double start_ms = start.tv_sec * 1000.0 + start.tv_usec / 1000.0;
    double end_ms = end.tv_sec * 1000.0 + end.tv_usec / 1000.0;
    return end_ms - start_ms;
}


void display_statistics() {
    time(&end_time);
    double run_time = difftime(end_time, start_time);
    printf("\n--- Ping Statistics ---\n");
    printf("%d packets transmitted, %d received, %.2f%% packet loss\n",
           packets_sent, packets_received,
           packets_sent > 0 ? (100.0 * (packets_sent - packets_received) / packets_sent) : 0.0);
    if (packets_received > 0) {
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
               min_rtt, total_rtt / packets_received, max_rtt);
    }
    printf("Total run time: %.2f seconds\n", run_time);
    exit(0);
}

void create_ipv4_icmp_packet(struct packet *pckt, uint16_t id, uint16_t sequence) {
    memset(pckt, 0, sizeof(struct packet));
    pckt->hdr.type = ICMP_ECHO; // ECHO_REQUEST
    pckt->hdr.code = 0;
    pckt->hdr.un.echo.id = htons(id);
    pckt->hdr.un.echo.sequence = htons(sequence);
    for (size_t i = 0; i < sizeof(pckt->msg) - 1; i++) {
        pckt->msg[i] = 'A' + (rand() % 26); // Fill message with letters
    }
    pckt->msg[sizeof(pckt->msg) - 1] = '\0';
    pckt->hdr.checksum = checksum(pckt, sizeof(struct packet));
    print_ipv4_packet_details(pckt);
}

void create_ipv6_icmp_packet(struct packet_ipv6 *pckt,struct sockaddr *src_addr, struct sockaddr *dest_addr, uint16_t id, uint16_t sequence) {
    memset(pckt, 0, sizeof(struct packet_ipv6));
    pckt->hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    pckt->hdr.icmp6_code = 0;
    pckt->hdr.icmp6_cksum = 0;

    pckt->id = id;
    pckt->sequence = sequence;

    pckt->hdr.icmp6_dataun.icmp6_un_data16[0] = htons(pckt->id);
    pckt->hdr.icmp6_dataun.icmp6_un_data16[1] = htons(pckt->sequence);

    for (size_t i = 0; i < sizeof(pckt->msg) - 1; i++) {
        pckt->msg[i] = 'A' + (rand() % 26); // Fill message with letters
    }
    pckt->msg[sizeof(pckt->msg) - 1] = '\0';
    pckt->hdr.icmp6_cksum = calculate_icmp6_checksum(src_addr,dest_addr ,pckt, sizeof(struct packet_ipv6));

    printf("create:\n");
    printf("\031[31mThis is red text\031[0m\n");
    print_ipv6_packet_details(pckt);
}

void send_ipv4_icmp_packet(int sock, struct sockaddr *dest_addr, socklen_t addr_len, uint16_t id, uint16_t sequence) {
    struct packet pckt;
    create_ipv4_icmp_packet(&pckt, id, sequence);
    printf("Before send (IPv4): \n");
    print_ipv4_packet_details(&pckt);

    if (sendto(sock, &pckt, sizeof(pckt), 0, dest_addr, addr_len) <= 0) {
        perror("Error sending IPv4 ICMP packet");
    } else {
        printf("After send (IPv4): Bytes sent\n");
        print_ipv4_packet_details(&pckt);
        packets_sent++;
    }
}

void send_ipv6_icmp_packet(int sock, struct sockaddr *dest_addr, struct sockaddr *src_addr,socklen_t addr_len, uint16_t id, uint16_t sequence) {
    struct packet_ipv6 pckt;
    create_ipv6_icmp_packet(&pckt, src_addr,dest_addr,id, sequence);
    printf("Before send (IPv6)\n");
    print_ipv6_packet_details(&pckt);

    if (sendto(sock, &pckt, sizeof(pckt), 0, dest_addr, addr_len) <= 0) {
        perror("Error sending IPv6 ICMP packet");
    } else {
        printf("After send (IPv6): Bytes sent\n");
        print_ipv6_packet_details(&pckt);
        packets_sent++;
    }
}

void receive_ipv4_icmp_reply(int sock, uint16_t id, struct timeval start) {
    uint8_t buffer[1024];
    struct sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 10000) <= 0) { // Timeout set to 10 seconds
        printf("Timeout occurred! No reply received.\n");
        return;
    }

    int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_addr, &addr_len);
    if (bytes_received <= 0) {
        perror("Error receiving ICMP reply");
        return;
    }

    struct iphdr *ip_header = (struct iphdr *)buffer;
    int ip_header_len = ip_header->ihl * 4;

    // Validate IP header length
    if (ip_header_len < (int)sizeof(struct iphdr) || ip_header_len > bytes_received) {
        printf("Invalid IP header length: %d\n", ip_header_len);
        return;
    }

    struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);

    printf("Received ICMP Packet:\n");

    // Validate ICMP packet size
    if (bytes_received < ip_header_len + (int)sizeof(struct icmphdr)) {
        printf("Packet too short: %d bytes\n", bytes_received);
        return;
    }

    // Debugging: Print sender IP
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)&sender_addr)->sin_addr, sender_ip, INET_ADDRSTRLEN);
    printf("Reply from: %s\n", sender_ip);

    // Validate ICMP type and ID
    if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == id) {
        struct packet *reply_packet = (struct packet *)(buffer + ip_header_len);
        print_ipv4_packet_details(reply_packet);

        struct timeval end;
        gettimeofday(&end, NULL);
        double rtt = calculate_rtt(start, end);
        printf("RTT: %.3f ms\n", rtt);

        // Update statistics
        packets_received++;
        total_rtt += rtt;
        if (min_rtt < 0 || rtt < min_rtt) min_rtt = rtt;
        if (rtt > max_rtt) max_rtt = rtt;
    } else {
        printf("Received unrelated ICMP packet. Type: %d, ID: %d (Expected ID: %d)\n",
               icmp->type, ntohs(icmp->un.echo.id), id);
    }
}

void receive_ipv6_icmp_reply(int sock, uint16_t id, struct timeval start) {
    uint8_t buffer[1024];
    struct sockaddr_storage sender_addr;
    socklen_t addr_len = sizeof(sender_addr);

    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    if (poll(&pfd, 1, 10000) <= 0) { // Timeout set to 10 seconds
        printf("Timeout occurred! No reply received.\n");
        return;
    }

    int bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender_addr, &addr_len);
    if (bytes_received <= 0) {
        perror("Error receiving ICMPv6 reply");
        return;
    }

    // Verify packet size
    if ((size_t)bytes_received < sizeof(struct packet_ipv6)) {
        printf("Packet too short: %d bytes\n", bytes_received);
        return;
    }


    // Map buffer to packet structure
    struct packet_ipv6 *pckt = (struct packet_ipv6 *)buffer;

    // Extract sender IP
    char sender_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sender_addr)->sin6_addr, sender_ip, INET6_ADDRSTRLEN);
    printf("Reply from: %s\n", sender_ip);

    // Extract and validate ICMPv6 fields
    uint16_t received_id = ntohs(pckt->id);
    uint16_t received_sequence = ntohs(pckt->sequence);

    printf("ICMP Type: %d\n", pckt->hdr.icmp6_type);
    printf("Expected ICMP Reply Type: %d\n", ICMP6_ECHO_REPLY);

    if (pckt->hdr.icmp6_type == ICMP6_ECHO_REPLY) {
        if (received_id == id) {
            printf("Received ICMPv6 reply with ID: %d, Sequence: %d\n", received_id, received_sequence);

            struct timeval end;
            gettimeofday(&end, NULL);
            double rtt = calculate_rtt(start, end);
            printf("RTT: %.3f ms\n", rtt);

            // Update statistics
            packets_received++;
            total_rtt += rtt;
            if (min_rtt < 0 || rtt < min_rtt) min_rtt = rtt;
            if (rtt > max_rtt) max_rtt = rtt;
        } else {
            printf("Received unrelated ID: %d\n", received_id);
        }
    } else {
        printf("Received unrelated ICMPv6 packet. Type: %d, ID mismatch (Expected: %d, Got: %d)\n",
               pckt->hdr.icmp6_type, id, received_id);
    }
}




int main(int argc, char *argv[]) {
    int opt;
    char *address = NULL;
    int protocol_type = 0;
    int count = 0;
    int flood = 0;

    signal(SIGINT, display_statistics);

    while ((opt = getopt(argc, argv, "a:t:c:f")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 't':
                protocol_type = atoi(optarg);
                break;
            case 'c':
                count = atoi(optarg);
                break;
            case 'f':
                flood = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -a <address> -t <4|6> [-c <count>] [-f]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!address || (protocol_type != 4 && protocol_type != 6)) {
        fprintf(stderr, "Error: Address and protocol type (-t) are required.\n");
        exit(EXIT_FAILURE);
    }
    
    int sock = socket(protocol_type == 4 ? AF_INET : AF_INET6, SOCK_RAW, protocol_type == 4 ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    if (count<=0) {
        count=COUNT;
    }
    if (protocol_type == 4) {
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &dest_addr.sin_addr) <= 0) {
            perror("Invalid address/ Address not supported");
            exit(EXIT_FAILURE);
        }

        printf("Target address: %s\n", address);

        time(&start_time);
        for (int i = 0; i < count ; i++) {
            struct timeval start;
            gettimeofday(&start, NULL);
            uint16_t id = (uint16_t)getpid() ^ (uint16_t)time(NULL);
            send_ipv4_icmp_packet(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr), id, i);
            receive_ipv4_icmp_reply(sock, id, start);
            if (!flood) sleep(1);
        }
    } else if (protocol_type == 6) {
        struct sockaddr_in6 dest_addr,src_addr;

        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin6_family = AF_INET6;

        if (inet_pton(AF_INET6, address, &dest_addr.sin6_addr) <= 0) {
            perror("Invalid address/ Address not supported");
            exit(EXIT_FAILURE);
        }

        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, "::", &src_addr.sin6_addr) <= 0) {
            perror("Invalid  source address");
            exit(EXIT_FAILURE);
        }

        printf("Target address: %s\n", address);

        time(&start_time);
        for (int i = 0; i < count ; i++) {
            struct timeval start;
            gettimeofday(&start, NULL);
            uint16_t id = (uint16_t)getpid() ^ (uint16_t)time(NULL);

            send_ipv6_icmp_packet(sock, (struct sockaddr *)&dest_addr,(struct sockaddr *)&src_addr, sizeof(dest_addr), id, i);
            receive_ipv6_icmp_reply(sock,id, start);
            if (!flood) sleep(1);
        }
    }

    display_statistics(0);
    close(sock);
    return 0;
}