/*
 * The Application.
 * TODO:say something
 *
 * Last modified by Qinyan on 7/10/15.
 * Email:qq416206@gmail.com
 *
 * Created by QinYan on 7/10/15.
 * Email:qq416206@gmail.com
 */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>

#define LENGTH 4096

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfad);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    //TODO:funcation here

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char *argv[]) {
    FILE *logfile;
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[LENGTH] __attribute__ ((aligned));
    int num;

    printf("Opening log file...\n");
    logfile = fopen("log", "a+");
    if (logfile == NULL) {
        perror("Error in open log file\n");
        exit(EXIT_FAILURE);
    }

    printf("Opening library handle...\n");
    h = nfq_open();
    if (h == NULL) {
        perror("Error during nfq_open()\n");
        exit(EXIT_FAILURE);
    }

    printf("Unbinding existing nf_queue handler for AF_INET (if any)...\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("Error druing nfq_unbind_pf()\n");
        exit(EXIT_FAILURE);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET...\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("Error druing nfq_bind_pf()\n");
        exit(EXIT_FAILURE);
    }

    printf("Binding this socket to queue '0'...\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (qh == NULL) {
        perror("Error during nfq_create_queue()\n");
        exit(EXIT_FAILURE);
    }

    printf("Setting copy_packet mode...\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Can't set packet_copy mode");
        exit(EXIT_FAILURE);
    }

    fd = nfq_fd(h);

    num = 0;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        printf("Pkt %d received...\n", num++);
        nfq_handle_packet(h, buf, rv);
    }

    printf("Unbinding from queue '0'...\n");
    nfq_destroy_queue(qh);

    printf("Closing library handle...\n");
    nfq_close(h);

    return EXIT_SUCCESS;
}