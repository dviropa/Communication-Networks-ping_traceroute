#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>

#define MAX_HOPS 3
#define PACKETS_PER_HOP 3
#define TIMEOUT 10000 // in milliseconds
#define BUFFER_SIZE 1024

// Global statistics
int packets_sent = 0;
int packets_received = 0;
int first_try = 1;

// Function prototypes
unsigned short calculate_checksum(void *data, int len);
void display_statistics();
int send_icmp_packet(int sock, struct sockaddr *dest_addr, socklen_t addr_len, int ttl, int sequence);
int poll_for_reply(int sock);
int receive_icmp_reply(int sock, struct timeval *start_time, struct sockaddr *reply_addr, socklen_t *reply_addr_len);
void traceroute(const char *destination_ip);
void handle_signal(int signum);

// Checksum function
unsigned short calculate_checksum(void *data, int len)
{
    unsigned short *ptr = data;
    unsigned int sum = 0;
    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)ptr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Signal handler for termination
void handle_signal(int signum)
{
    printf("\nReceived signal %d\n", signum);
    display_statistics();
    exit(EXIT_SUCCESS);
}

// Display statistics function
void display_statistics()
{
    printf("\n--- Traceroute statistics ---\n");
    printf("%d packets transmitted, %d received, %.2f%% packet loss\n",
           packets_sent, packets_received, ((packets_sent - packets_received) / (float)packets_sent) * 100);
}
// Poll for reply function
int poll_for_reply(int sock) {#בדוק אם יש נתונים זמינים לקריאה על סוקט נתון
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;

    int result = poll(&pfd, 1, TIMEOUT);#  TIMEOUT  סוקט אחד לבדיקה בזמן    &pfd: מצביע למערך של מבני pollfd
    if (result < 0) {# שגיעת מערכת 
        perror("poll failed");
        return -1;
    } else if (result == 0) {#TIMEOUT חלף
        printf("*  ");
        return 0;
    }
    return 1;
}

// Send ICMP packet function
int send_icmp_packet(int sock, struct sockaddr *dest_addr, socklen_t addr_len, int ttl, int sequence)
{
    struct icmphdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.un.echo.sequence = sequence;
    icmp_hdr.checksum = calculate_checksum(&icmp_hdr, sizeof(icmp_hdr));

    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    {
        perror("Set TTL failed");
        return -1;
    }

    if (sendto(sock, &icmp_hdr, sizeof(icmp_hdr), 0, dest_addr, addr_len) < 0)
    {
        perror("Send failed");
        return -1;
    }

    packets_sent++;
    return 0;
}

// Receive ICMP reply function
int receive_icmp_reply(int sock, struct timeval *start_time, struct sockaddr *reply_addr, socklen_t *reply_addr_len)
{
    char buffer[BUFFER_SIZE];
    struct timeval end_time;

    if (recvfrom(sock, buffer, sizeof(buffer), 0, reply_addr, reply_addr_len) > 0)
    {
        gettimeofday(&end_time, NULL);
        long rtt = (end_time.tv_sec - start_time->tv_sec) * 1000 + (end_time.tv_usec - start_time->tv_usec) / 1000;

        struct sockaddr_in *addr4 = (struct sockaddr_in *)reply_addr;
        char ip4_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &addr4->sin_addr, ip4_str, sizeof(ip4_str));#ממירה כתובת IP בפורמט בינארי (network byte order) לכתובת טקסטואלית קריאה
        if (first_try)
        {
            printf("%s", ip4_str);#  הדפסת כתובת השולח פעם אחת מונע חזרתיות
            first_try = 0;
        }
        printf(" %ldms", rtt);# הדפסת ה זמן שלקח לחבילה להגיע 

        packets_received++;
        return 1;
    }
    return 0;
}

// Traceroute function
void traceroute(const char *destination_ip)
{
    struct sockaddr_in dest_addr4;
    socklen_t addr_len;

    memset(&dest_addr4, 0, sizeof(dest_addr4));

    if (inet_pton(AF_INET, destination_ip, &dest_addr4.sin_addr) > 0)
    {
        dest_addr4.sin_family = AF_INET;
        addr_len = sizeof(dest_addr4);
    }
    else
    {
        perror("Invalid destination IP address");
        exit(EXIT_FAILURE);
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct timeval timeout = {TIMEOUT / 1000, (TIMEOUT % 1000) * 1000};
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("Set socket timeout failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("traceroute to %s, %d hops max\n", destination_ip, MAX_HOPS);
    struct sockaddr_storage reply_addr;
    for (int ttl = 1; ttl <= MAX_HOPS; ttl++)
    {
        printf("%2d  ", ttl);
        int success = 0;
        first_try = 1;

        for (int i = 0; i < PACKETS_PER_HOP; i++)
        {
            struct timeval start_time;
            gettimeofday(&start_time, NULL);

            if (send_icmp_packet(sock, (struct sockaddr *)&dest_addr4, addr_len, ttl, ttl * PACKETS_PER_HOP + i) == 0)
            {

                socklen_t reply_addr_len = sizeof(reply_addr);

                if (poll_for_reply(sock) > 0)
                {
                    if (receive_icmp_reply(sock, &start_time, (struct sockaddr *)&reply_addr, &reply_addr_len))
                    {
                        if (((struct sockaddr_in *)&reply_addr)->sin_addr.s_addr == dest_addr4.sin_addr.s_addr)
                        {
                            printf("\nReached destination\n");
                            display_statistics();
                            close(sock);
                            return;
                        }
                        success = 1;
                    }
                }
            }
        }

        printf("\n");
        if (!success)#אם לא התקבלו תשובות מכל החבילות עבור TTL מסוים
        {
            printf("Destination unreachable\n");
            break;
        }
    }
    if (!(((struct sockaddr_in *)&reply_addr)->sin_addr.s_addr == dest_addr4.sin_addr.s_addr))
    {
        printf("Destination unreachable\n");
    }
    display_statistics();
    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc != 3 || strcmp(argv[1], "-a") != 0)#מוודא שהמשתמש הזין בדיוק שני פרמטרים (שם התוכנית וכתובת היעד). או  בודק שהפרמטר הראשון הוא -a (כפי שדורש השימוש)
    {
        printf("Usage: sudo ./traceroute -a <destination IP>\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);#תטפל בניקוי משאבים והפסקת התוכנית בצורה מסודרת.
    traceroute(argv[2]);# קיראה לתוכנית עם כתובת היעד
    return EXIT_SUCCESS;
}