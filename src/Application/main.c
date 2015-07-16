/*
 * The Application
 *
 * User level application.A lot of things.
 *
 * Last modified by Qinyan on 7/17/15.
 * Email:qq416206@gmail.com
 *
 * Created by QinYan on 7/10/15.
 * Email:qq416206@gmail.com
 */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>

#define LENGTH 4096
#define IPLENGTH 16
#define LOGLENGTH 512

int num = 0;  ////Count the packets.
FILE *logfile, *filterlist;

/*
 * Data structure : linklist for filter ip. (Don't use)
 */
//typedef struct filter
//{
//    char *ip;
//    struct filter *filter_prev,*filter_next;
//} filterNode, *filterList;
//
//int insertList(filterNode *fn, char* ip)
//{
//    filterNode *nextfilter, *newfilter;
//
//    newfilter = (filterNode *)malloc(sizeof(filterNode));
//    if (newfilter == NULL)
//    {
//        printf("Insert filterlist failed!");
//        return 2;
//    }
//
//    newfilter->ip = ip;
//
//    if (fn->filter_next == NULL)
//    {
//        newfilter->filter_next = NULL;
//    }
//    else
//    {
//        nextfilter = fn->filter_next;
//        newfilter->filter_next = nextfilter;
//        nextfilter->filter_prev = newfilter;
//    }
//    fn->filter_next = newfilter;
//    newfilter->filter_prev = fn;
//
//    return 0;
//}

/*
 * This function is writing logfile.
 */
void writeLog(FILE *filesteam, char *str)
{
    char buff[LOGLENGTH];
    time_t timep;
    struct tm *p;

    time(&timep);
    p = localtime(&timep);
    memset(buff, 0, sizeof(buff));
    sprintf(buff, "[%d-%d-%d %d:%d:%d]: ", (1900+p->tm_year), (1+p->tm_mon), p->tm_mday, p->tm_hour,p->tm_min, p->tm_sec+1);
    strcat(buff, str);
    strcat(buff, "\n");

    fwrite(buff, 1, strlen(buff), filesteam);
    fflush(filesteam);
}

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
 * Domain names resolution
 */
struct addrinfo *getipbyhostname(char *hostname)
{
    struct addrinfo *res,
    hints = {
            .ai_flags = AI_ADDRCONFIG,
            .ai_family = PF_INET,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
            .ai_addrlen = 0,
            .ai_canonname = NULL,
            .ai_addr = NULL,
            .ai_next = NULL
    };

    int result = getaddrinfo(hostname, NULL, &hints, &res);

    if (result != 0)
    {
        printf("Can not get host by hostname: %s", hostname);
        return NULL;
    }

    return res;
}

/*
 * This function is used to process packets.
 */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pload;
    char ip[IPLENGTH];
    char ipc[IPLENGTH];
    char str[IPLENGTH];
    char logstr[LOGLENGTH];

    ph = nfq_get_msg_packet_hdr(nfad);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }

    nfq_get_payload(nfad, &pload);
    struct iphdr *iph = (struct iphdr*)pload;

    sprintf(ip, "%d.%d.%d.%d", ((unsigned char *)&iph->daddr)[0],
                               ((unsigned char *)&iph->daddr)[1],
                               ((unsigned char *)&iph->daddr)[2],
                               ((unsigned char *)&iph->daddr)[3]);

    rewind(filterlist);
    fgets(str, sizeof(str), filterlist);

    while (fgets(str, sizeof(str), filterlist) != NULL)
    {
        if (strncasecmp(str, "-----", 5) == 0)
        {
            continue;
        }

        sprintf(ipc, "%s\n", ip);

        if(strcmp(ipc, str) == 0)
        {
            printf("Packet %d from %s dropped...(Press 'Q' to exit the program)\n", num++, ip);

            sprintf(logstr, "Packet from %s dropped.", ip);
            writeLog(logfile, logstr);

            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }

    printf("Packet %d from %s passed...(Press 'Q' to exit the program)\n", num++, ip);

    sprintf(logstr, "Packet from %s passed.", ip);
    writeLog(logfile, logstr);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/*
 * Main fucntion
 */
int main(int argc, char *argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[LENGTH] __attribute__ ((aligned));
    char ch;

    int i = 1;
    char *ipfilter = "-i";
    char *hostnamefilter = "-h";

    printf("Opening log file...");
    logfile = fopen("log", "a+");
    if (logfile == NULL)
    {
        perror("Error in open log file\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Opening filterlist file...");
    filterlist = fopen("filterlist", "a+");
    if (filterlist == NULL)
    {
        perror("Error in open filterlist file\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

//    filterList fl;
//    fl = (filterNode *)malloc(sizeof(filterNode));

    while (argv[i] != NULL)
    {
        if (strcmp(argv[i], ipfilter) == 0)
        {
            i++;
            if (argv[i] == NULL)
            {
                printf("Parameter error!");
                exit(EXIT_FAILURE);
            }
            fputs(argv[i],filterlist);
            fputs("\n",filterlist);
        }
        else if (strcmp(argv[i], hostnamefilter) == 0)
        {
            i++;
            if (argv[i] == NULL)
            {
                printf("Parameter error!");
                exit(EXIT_FAILURE);
            }

            struct addrinfo *res, *res0;
            res0 = getipbyhostname(argv[i]);

            fputs("-----",filterlist);
            fputs(argv[i], filterlist);
            fputs("\n",filterlist);

            for (res = res0; res; res=res->ai_next)
            {
                struct sockaddr_in *addrin = (struct sockaddr_in *)res->ai_addr;
                fputs(inet_ntoa(addrin->sin_addr),filterlist);
                fputs("\n",filterlist);
            }

            fputs("-----\n",filterlist);

            freeaddrinfo(res0);
        }
        else
        {
            printf("Parameter error!");
            exit(EXIT_FAILURE);
        }
        i++;
    }

    fflush(filterlist);

    printf("-----My Netfilter Kernel Module Start-----\n");
    system("insmod /root/ClionProjects/Linux_Netfilter_Program/src/KernelModule/myhook.ko");  //Change kernel module path in your system!!
    sleep(10);  //Make sure that the module is loaded.

    printf("Opening library handle...");
    h = nfq_open();
    if (h == NULL)
    {
        perror("Error during nfq_open()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Unbinding existing nf_queue handler for AF_INET (if any)...");
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        perror("Error druing nfq_unbind_pf()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET...");
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        perror("Error druing nfq_bind_pf()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Binding this socket to queue '0'...");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (qh == NULL)
    {
        perror("Error during nfq_create_queue()\n");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    printf("Setting copy_packet mode...");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        perror("Can't set packet_copy mode");
        exit(EXIT_FAILURE);
    }
    printf("success!\n");

    fd = nfq_fd(h);

    writeLog(logfile, "-----Start filter-----");

    changeMode(1);  //Turn on kbhit().

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
    {
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

    writeLog(logfile, "-----Stop filter-----");

    printf("Closing log file...");
    fclose(logfile);
    printf("success!\n");

    printf("Closing filterlist file...");
    fclose(filterlist);
    printf("success!\n");

    return EXIT_SUCCESS;
}