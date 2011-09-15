/*
 *   Janus, a portable, unified and lightweight interface for mitm
 *   applications over the traffic directed to the default gateway.
 *
 *   Copyright (C) 2011 evilaliv3 <giovanni.pellerano@evilaliv3.org>
 *                      vecna <vecna@delirandom.net>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <event.h>
#include <pcap.h>

#include "janus.h"
#include "utils.h"
#include "packet_queue.h"

#define NETWORK    0
#define KROWTEN    1

enum mitm_t
{
    FDIF = 0,
    FDMITM = 1,
    FDMITMATTACH = 2
};

struct janus_config conf;

static struct event_base *ev_base;

static uint16_t pbuf_len;
static struct packets *pbufs;

static pcap_t *capnet;
static char *macpkt;
struct event net_ev_recv;
struct packet *net_pbuf_recv;
struct sockaddr_in krowten_sin;

static struct ethernet_header netif_send_hdr, netif_recv_hdr, fake_send_hdr;

struct mitm_descriptor
{
    int fd[3]; /* FDIF | FDMITM | FDMITMATTACH */
    struct event ev_send; /* FDIF */
    struct event ev_attach; /* FDMITMATTACH */
    struct bufferevent * mitm_bufferevent; /* FDMITM */
    ssize_t(*fd_send)(int sockfd, struct packet * pbuf); /* FDIF */
    struct packet *pbuf_send; /* FDIF */
    struct packet *pbuf_mitm; /* FDMITM */
    struct packet_queue * pqueue; /* FDIF */
};

static struct mitm_descriptor mitm_desc[2];

static void setfdflag(int fd, long flags)
{
    long tmpflags;
    if (((tmpflags = fcntl(fd, F_GETFD)) == -1) || (fcntl(fd, F_SETFD, tmpflags | flags) == -1))
        runtime_exception("unable to set fd flags %u on fd %u (F_GETFD/F_SETFD)", fd, flags);
}

static void setflflag(int fd, long flags)
{
    long tmpflags;
    if (((tmpflags = fcntl(fd, F_GETFL)) == -1) || (fcntl(fd, F_SETFL, tmpflags | flags) == -1))
        runtime_exception("unable to set fl flags %u on fd %u (F_GETFL/F_SETFL)", fd, flags);
}

static void parseMAC(const char *str, unsigned char *buf)
{
    uint8_t i;
    uint32_t tmp_mac[ETH_ALEN];
    sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", &tmp_mac[0], &tmp_mac[1], &tmp_mac[2], &tmp_mac[3], &tmp_mac[4], &tmp_mac[5]);
    for (i = 0; i < ETH_ALEN; ++i)
        buf[i] = tmp_mac[i];
}

static struct packet* bufferedRead(struct mitm_descriptor *desc)
{
    return queue_pop_front(desc->pqueue, &desc->pbuf_send);
}

static void bufferedWrite(struct mitm_descriptor *desc, enum mitm_t i, struct packet *pbuf)
{
    if ((i == FDIF) && (desc->fd[FDMITM] != -1))
    {
        uint16_t size = htons(pbuf->size);
        bufferevent_write(desc->mitm_bufferevent, &size, sizeof (size));
        bufferevent_write(desc->mitm_bufferevent, pbuf->buf, pbuf->size);
        pbuf_release(pbufs, pbuf);
    }
    else
    {
        if (desc->pqueue->count == 0)
            event_add(&desc->ev_send, NULL);

        queue_push_back(desc->pqueue, pbuf);
    }
}

static ssize_t send_in(int sockfd, struct packet *pbuf)
{
    return sendto(mitm_desc[KROWTEN].fd[FDIF], pbuf->buf, pbuf->size, 0, (struct sockaddr *) &krowten_sin, sizeof (krowten_sin));
}

static ssize_t send_out(int sockfd, struct packet *pbuf)
{
    memcpy(&macpkt[ETH_HLEN], pbuf->buf, pbuf->size);

    if (pcap_inject(capnet, macpkt, ETH_HLEN + pbuf->size) != -1)
        return pbuf->size;
    else
        return -1;
}

static void recv_cb(int f, short event, void *arg)
{
    if ((net_pbuf_recv != NULL) || ((net_pbuf_recv = pbuf_acquire(pbufs)) != NULL))
    {
        struct pcap_pkthdr header;
        const u_char * const packet = pcap_next(capnet, &header);

        if ((packet != NULL) && (header.len == header.caplen))
        {
            net_pbuf_recv->size = header.len - ETH_HLEN;
            net_pbuf_recv->size = (net_pbuf_recv->size > pbuf_len) ? pbuf_len : net_pbuf_recv->size;
            memcpy(net_pbuf_recv->buf, packet + ETH_HLEN, net_pbuf_recv->size);

            if (!memcmp(packet, &netif_recv_hdr, 2 * ETH_ALEN))
                bufferedWrite(&mitm_desc[NETWORK], FDIF, net_pbuf_recv);

            else if (!memcmp(packet, &fake_send_hdr, 2 * ETH_ALEN))
                bufferedWrite(&mitm_desc[KROWTEN], FDIF, net_pbuf_recv);

            net_pbuf_recv = NULL;

            return;
        }
    }
}

static void send_cb(int f, short event, void *arg)
{
    struct mitm_descriptor * const desc = arg;

    if ((desc->pbuf_send != NULL) || ((desc->pbuf_send = bufferedRead(desc)) != NULL))
    {
        const ssize_t ret = desc->fd_send(desc->fd[FDIF], desc->pbuf_send);

        if (ret == desc->pbuf_send->size)
        {
            pbuf_release(pbufs, desc->pbuf_send);
            desc->pbuf_send = NULL;

            if (desc->pqueue->count == 0)
                event_del(&desc->ev_send);

            return;
        }
            
        if (errno != EAGAIN)
            event_loopbreak();
    }
}

static void mitm_rs_error(struct mitm_descriptor* desc)
{
    J_CLOSE(&desc->fd[FDMITM]);
    J_BUFFEREVENT_FREE(&desc->mitm_bufferevent);

    event_add(&desc->ev_attach, NULL);
}

static void mitmrecv_cb(struct bufferevent *sabe, void *arg)
{
    struct mitm_descriptor * const desc = arg;

    if (desc->pbuf_mitm == NULL)
    {
        desc->pbuf_mitm = pbuf_acquire(pbufs);
        if (desc->pbuf_mitm == NULL)
            return;

        if (bufferevent_read(desc->mitm_bufferevent, &desc->pbuf_mitm->size, sizeof (uint16_t)) != sizeof (uint16_t))
        {
            mitm_rs_error(desc);
            return;
        }

        desc->pbuf_mitm->size = ntohs(desc->pbuf_mitm->size);
        if(desc->pbuf_mitm->size == 0 || desc->pbuf_mitm->size > pbuf_len )
        {
            mitm_rs_error(desc);
            return;
        }

        bufferevent_setwatermark(desc->mitm_bufferevent, EV_READ, desc->pbuf_mitm->size, desc->pbuf_mitm->size);
    }
    else
    {
        if (bufferevent_read(desc->mitm_bufferevent, desc->pbuf_mitm->buf, desc->pbuf_mitm->size) != desc->pbuf_mitm->size)
        {
            mitm_rs_error(desc);
            return;
        }

        bufferedWrite(desc, FDMITM, desc->pbuf_mitm);
        desc->pbuf_mitm = NULL;
        bufferevent_setwatermark(desc->mitm_bufferevent, EV_READ, sizeof (uint16_t), sizeof (uint16_t));
    }
}

static void mitm_rs_error_cb(struct bufferevent *sabe, short what, void *arg)
{
    mitm_rs_error(arg);
}

static void mitmattach_cb(int f, short event, void *arg)
{
    struct mitm_descriptor * const desc = arg;

    desc->fd[FDMITM] = accept(desc->fd[FDMITMATTACH], NULL, NULL);
    if (desc->fd[FDMITM] != -1)
    {
        /*
         * TODO:
         * every time a client attached to Janus, Janus's actual configuration must be sent.
         * this would be probabily done using a JSON object for portability reasons.
         */

        event_del(&desc->ev_attach);
        setfdflag(desc->fd[FDMITM], FD_CLOEXEC);
        setflflag(desc->fd[FDMITM], O_NONBLOCK);
        desc->mitm_bufferevent = bufferevent_new(desc->fd[FDMITM], mitmrecv_cb, NULL, mitm_rs_error_cb, desc);
        bufferevent_setwatermark(desc->mitm_bufferevent, EV_READ, 2, 2);
        bufferevent_enable(desc->mitm_bufferevent, EV_READ);
    }
    else
    {
        if (errno != EAGAIN)
            event_loopbreak();
    }
}

static int setupMitmAttach(uint16_t port)
{
    int fd = -1;
    const int on = 1;

    struct sockaddr_in ssin;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        runtime_exception("unable to open socket");

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (int));

    memset(&ssin, 0, sizeof (struct sockaddr_in));
    ssin.sin_family = AF_INET;
    ssin.sin_port = htons(port);
    if (!inet_aton(conf.listen_ip, (struct in_addr *) &ssin.sin_addr.s_addr))
        runtime_exception("invalid listening address provided");

    if (bind(fd, (struct sockaddr *) &ssin, sizeof (struct sockaddr_in)) == -1)
        runtime_exception("unable to bind");

    if (listen(fd, 0) == -1)
        runtime_exception("unable to listen");

    return fd;
}

static void setupNETWORK(void)
{
    char ebuf[PCAP_ERRBUF_SIZE];

    capnet = pcap_open_live(get_sysmap_str('2'), 65535, 0, 0, ebuf);
    if (capnet == NULL)
        runtime_exception("unable to open pcap handle on interface %s: %s ", get_sysmap_str('2'), ebuf);

    mitm_desc[NETWORK].fd[FDIF] = pcap_fileno(capnet);

    setfdflag(mitm_desc[NETWORK].fd[FDIF], FD_CLOEXEC);

    if (pcap_setnonblock(capnet, 1, ebuf) == -1)
        runtime_exception("unable to set pcap handle in non blocking mode on interface %s", get_sysmap_str('2'));

    mitm_desc[NETWORK].fd[FDMITMATTACH] = setupMitmAttach(conf.listen_port_in);
}

static void setupKROWTEN(void)
{
    const int one = 1;
    const int *val = &one;

    mitm_desc[KROWTEN].fd[FDIF] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (mitm_desc[KROWTEN].fd[FDIF] == -1)
        runtime_exception("unable to setup raw socket for local delivery: %s", strerror(errno));

    setsockopt(mitm_desc[KROWTEN].fd[FDIF], IPPROTO_IP, IP_HDRINCL, val, sizeof (one));

    memset(&krowten_sin, 0, sizeof (krowten_sin));
    krowten_sin.sin_family = AF_INET;

    setfdflag(mitm_desc[KROWTEN].fd[FDIF], FD_CLOEXEC);
    setflflag(mitm_desc[KROWTEN].fd[FDIF], O_NONBLOCK);

    inet_aton(get_sysmap_str('3'), (struct in_addr *) &krowten_sin.sin_addr.s_addr);

    mitm_desc[KROWTEN].fd[FDMITMATTACH] = setupMitmAttach(conf.listen_port_out);
}

/* 
 * in janus bootstrap the first and the second sections of the configuration commands
 * are executed
 */
void JANUS_Bootstrap(void)
{
    uint8_t i, j;

    janus_commands_file_setup(OSSELECTED);

    /* now we had the commands stored and the infos detected */
    /* execute "informative" commands (second section in the commands file) */

    capnet = NULL;

    /* acquire mac address inside the ethernet struct */
    parseMAC(get_sysmap_str('6'), netif_send_hdr.dst_ethernet);
    parseMAC(get_sysmap_str('5'), netif_send_hdr.src_ethernet);

    memcpy(netif_recv_hdr.dst_ethernet, netif_send_hdr.src_ethernet, ETH_ALEN);
    memcpy(netif_recv_hdr.src_ethernet, netif_send_hdr.dst_ethernet, ETH_ALEN);

    memcpy(fake_send_hdr.dst_ethernet, netif_send_hdr.src_ethernet, ETH_ALEN);
    memcpy(fake_send_hdr.src_ethernet, netif_send_hdr.src_ethernet, ETH_ALEN);

    netif_send_hdr.link_type = netif_recv_hdr.link_type = fake_send_hdr.link_type = htons(ETH_P_IP);

    pbuf_len = atoi(get_sysmap_str('4'));

    pbufs = pbufs_malloc(conf.pqueue_len, pbuf_len);

    J_MALLOC(macpkt, ETH_HLEN + pbuf_len);

    memcpy(macpkt, &netif_send_hdr, ETH_HLEN);

    memset(&mitm_desc, 0, sizeof (mitm_desc));

    mitm_desc[NETWORK].fd_send = send_in;
    mitm_desc[KROWTEN].fd_send = send_out;

    for (i = 0; i < 2; ++i)
    {
        mitm_desc[i].pqueue = queue_malloc(pbufs);

        for (j = 0; j < 3; ++j)
            mitm_desc[i].fd[j] = -1;
    }
}

void JANUS_Init(void)
{
    setupNETWORK();
    setupKROWTEN();

    /* ;7 add a fake arp entry */
    sysmap_command('7');

    /* ;9 add a firewall rule able to drop incoming traffic with src mac addr $6 */
    sysmap_command('9');

    /* ;C add a firewall rule able to NAT the traffic through the network */
    sysmap_command('B');
}

void JANUS_EventLoop(void)
{
    uint8_t i;

    ev_base = event_init();

    event_set(&net_ev_recv, mitm_desc[NETWORK].fd[FDIF], EV_READ | EV_PERSIST, recv_cb, NULL);
    event_add(&net_ev_recv, NULL);

    for (i = 0; i < 2; ++i)
    {
        event_set(&mitm_desc[i].ev_send, mitm_desc[i].fd[FDIF], EV_WRITE | EV_PERSIST, send_cb, &mitm_desc[i]);

        event_set(&mitm_desc[i].ev_attach, mitm_desc[i].fd[FDMITMATTACH], EV_READ, mitmattach_cb, &mitm_desc[i]);
        event_add(&mitm_desc[i].ev_attach, NULL);
    }

    event_dispatch();
}

void JANUS_Reset(void)
{
    uint8_t i, j;

    /* ;8 del the fake arp entry added with $7 */
    sysmap_command('8');

    /* ;A delete the firewall rule added with $9 */
    sysmap_command('A');

    /* ;C delete the firewall rule added with $B */
    sysmap_command('C');

    J_PCAP_CLOSE(&capnet);

    for (i = 0; i < 2; ++i)
    {
        queue_reset(mitm_desc[i].pqueue);

        J_PBUF_RELEASE(&mitm_desc[i].pbuf_send);
        J_PBUF_RELEASE(&mitm_desc[i].pbuf_mitm);
        J_BUFFEREVENT_FREE(&mitm_desc[i].mitm_bufferevent);

        for (j = 0; j < 3; ++j)
            J_CLOSE(&mitm_desc[i].fd[j]);
    }

    event_base_free(ev_base);
}

void JANUS_Shutdown(void)
{
    uint8_t i;

    for (i = 0; i < 2; ++i)
        queue_free(mitm_desc[i].pqueue);

    pbufs_free(pbufs);

    free(macpkt);

    free_cmd_structures();
}
