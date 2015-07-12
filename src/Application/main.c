/*
 * The Application
 *
 * TODO:say something
 *
 * Last modified by Qinyan on 7/12/15.
 * Email:qq416206@gmail.com
 *
 * Created by QinYan on 7/10/15.
 * Email:qq416206@gmail.com
 */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <netdb.h>
#include <arpa/inet.h>

#define LENGTH 4096

static int num;
static char *filter;  //TODO:DEBUG

/*
 * This function is kbhit() in Linux.(Other people's achievement)
 */
int kbhit(void)
{
    struct timeval tv;
    fd_set rdfs;

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    FD_ZERO(&rdfs);
    FD_SET (STDIN_FILENO, &rdfs);

    select(STDIN_FILENO+1, &rdfs, NULL, NULL, &tv);

    return FD_ISSET(STDIN_FILENO, &rdfs);
}

/*
 * Using changeMode(1) to turn on kbhit() and using changeMode(0) to turn off.
 */
void changeMode(int dir)
{
    static struct termios oldt, newt;

    if (dir == 1)
    {
        tcgetattr( STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~( ICANON | ECHO );
        tcsetattr( STDIN_FILENO, TCSANOW, &newt);
    }
    else
    {
        tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
    }
}

/*
 * Hostname transforms to IP
 */
char* hostnametoip(char *hostname)
{
    struct hostent *host;
    char *nul = NULL;

    host = gethostbyname(hostname);

    if (host == NULL)
    {
        printf("Can not get host by hostname: %s", hostname);
        return nul;
    }

    return inet_ntoa(*((struct in_addr*)host->h_addr_list));
}

/*
 * This function is used to process packets.
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pload;
    char ip[16];

    ph = nfq_get_msg_packet_hdr(nfad);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    nfq_get_payload(nfad, &pload);
    struct iphdr *iph = (struct iphdr*)pload;

    sprintf(ip, "%d.%d.%d.%d", ((unsigned char *)&iph->saddr)[0],
                               ((unsigned char *)&iph->saddr)[1],
                               ((unsigned char *)&iph->saddr)[2],
                               ((unsigned char *)&iph->saddr)[3]);

    //TODO:DEBUG
    if (ip == filter)
    {
        printf("Packet %d from %s dropped...(Press 'Q' to exit the program)\n", num++, ip);

        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    printf("Packet %d from %s accepted...(Press 'Q' to exit the program)\n", num++, ip);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/*
 * Main fucntion
 */
int main(int argc, char *argv[]) {
    FILE *logfile;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[LENGTH] __attribute__ ((aligned));
    char ch;

    printf("Opening log file...");
    logfile = fopen("log", "a+");
    if (logfile == NULL) {
        perror("Error in open log file\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("-----My Netfilter Kernel Module Start-----\n");
    system("insmod /root/ClionProjects/Linux_Netfilter_Program/src/KernelModule/myhook.ko");  //Change kernel module path in your system!!
    sleep(10);  //Make sure that the module is loaded.

    printf("Opening library handle...");
    h = nfq_open();
    if (h == NULL) {
        perror("Error during nfq_open()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Unbinding existing nf_queue handler for AF_INET (if any)...");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("Error druing nfq_unbind_pf()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET...");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("Error druing nfq_bind_pf()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Binding this socket to queue '0'...");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (qh == NULL) {
        perror("Error during nfq_create_queue()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Setting copy_packet mode...");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Can't set packet_copy mode");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    fd = nfq_fd(h);

    changeMode(1);  //Turn on kbhit().

    filter = hostnametoip("www.sina.com");  //TODO:DEBUG

    num = 0;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);

        if (kbhit())  //Press Q to exit the program.
        {
            ch = getchar();
            if (ch == 'Q')
            {
                break;
            }
        }
    }

    changeMode(0);  //Turn off kbhit().

    printf("Unbinding from queue '0'...");
    nfq_destroy_queue(qh);
    printf("success!\n");

    printf("Closing library handle...");
    nfq_close(h);
    printf("success!\n");

    printf("-----My Netfilter Kernel Module Stop-----\n");
    system("rmmod myhook");
    sleep(10);  //Make sure that the module is unloaded.

    printf("Closing log file...");
    fclose(logfile);
    printf("success!\n");

    return EXIT_SUCCESS;
}