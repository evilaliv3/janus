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

#define NET    0
#define TUN    1

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

static struct ethernet_header netif_send_hdr;
static struct ethernet_header netif_recv_hdr;

struct mitm_descriptor
{
    int fd[3]; /* FDIF | FDMITM | FDMITMATTACH */
    struct event ev_send; /* FDIF */
    struct event ev_recv[3]; /* FDIF | FDMITM | FDMITMATTACH */
    ssize_t(*fd_recv)(int sockfd, struct packet * pbuf); /* FDIF */
    ssize_t(*fd_send)(int sockfd, struct packet * pbuf); /* FDIF */
    struct packet * pbuf_recv[2]; /* FDIF | FDMITM */
    struct packet* pbuf_send; /* FDIF */
    struct packet_queue * pqueue; /* FDIF */
    struct bufferevent * mitm_bufferevent; /* FDMITM */

    struct mitm_descriptor *target;

    uint8_t first_mitm_connection;
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
    struct mitm_descriptor * const target = desc->target;

    if ((i == FDIF) && (desc->fd[FDMITM] != -1))
    {
        uint16_t size = htons(pbuf->size);
        bufferevent_write(desc->mitm_bufferevent, &size, sizeof (size));
        bufferevent_write(desc->mitm_bufferevent, pbuf->buf, pbuf->size);
        pbuf_release(pbufs, pbuf);
    }
    else
    {
        if (target->pqueue->count == 0)
            event_add(&target->ev_send, NULL);

        queue_push_back(target->pqueue, pbuf);
    }
}

static ssize_t netif_recv(int sockfd, struct packet *pbuf)
{
    struct pcap_pkthdr header;
    const u_char * const packet = pcap_next(capnet, &header);

    if (header.len != header.caplen)
        return -1;

    if ((packet != NULL) && !memcmp(packet, &netif_recv_hdr, ETH_HLEN))
    {
        int32_t len = header.len - ETH_HLEN;
        len = (len > pbuf_len) ? pbuf_len : len;
        memcpy(pbuf->buf, packet + ETH_HLEN, len);
        return len;
    }

    errno = EAGAIN;
    return -1;
}

static ssize_t netif_send(int sockfd, struct packet *pbuf)
{
    memcpy(&macpkt[ETH_HLEN], pbuf->buf, pbuf->size);

    if (pcap_inject(capnet, macpkt, ETH_HLEN + pbuf->size) != -1)
        return pbuf->size;
    else
        return -1;
}

static ssize_t tunif_recv(int sockfd, struct packet *pbuf)
{
    return read(sockfd, pbuf->buf, pbuf_len);
}

static ssize_t tunif_send(int sockfd, struct packet *pbuf)
{
    return write(sockfd, pbuf->buf, pbuf->size);
}

static void recv_cb(int f, short event, void *arg)
{
    struct mitm_descriptor * const desc = arg;

    struct packet * * const pbuf = &desc->pbuf_recv[FDIF];

    if ((*pbuf != NULL) || ((*pbuf = pbuf_acquire(pbufs)) != NULL))
    {
        ssize_t ret = desc->fd_recv(desc->fd[FDIF], *pbuf);

        if (ret > 0)
        {
            (*pbuf)->size = ret;
            bufferedWrite(desc, FDIF, *pbuf);
            *pbuf = NULL;
        }
        else
        {
            if (errno != EAGAIN)
                event_loopbreak();
        }
    }
}

static void send_cb(int f, short event, void *arg)
{
    struct mitm_descriptor * const desc = arg;

    struct packet * * const pbuf = &desc->pbuf_send;

    if (*pbuf != NULL || ((*pbuf = bufferedRead(desc)) != NULL))
    {
        const ssize_t ret = desc->fd_send(desc->fd[FDIF], *pbuf);

        if (ret == (*pbuf)->size)
        {
            pbuf_release(pbufs, *pbuf);
            *pbuf = NULL;

            if (desc->pqueue->count == 0)
                event_del(&desc->ev_send);
        }
        else
        {
            if (errno != EAGAIN)
                event_loopbreak();
        }
    }
}

static void mitm_rs_error(struct mitm_descriptor* desc)
{
    J_CLOSE(&desc->fd[FDMITM]);
    J_BUFFEREVENT_FREE(&desc->mitm_bufferevent);

    event_add(&desc->ev_recv[FDMITMATTACH], NULL);
}

static void mitmrecv_cb(struct bufferevent *sabe, void *arg)
{
    struct mitm_descriptor * const desc = arg;

    struct packet * * const pbuf = &desc->pbuf_recv[FDMITM];

    if (*pbuf == NULL)
    {
        *pbuf = pbuf_acquire(pbufs);
        if (*pbuf == NULL)
            return;

        if (bufferevent_read(desc->mitm_bufferevent, &(*pbuf)->size, sizeof (uint16_t)) != sizeof (uint16_t))
        {
            mitm_rs_error(desc);
            return;
        }

        (*pbuf)->size = ntohs((*pbuf)->size);
        bufferevent_setwatermark(desc->mitm_bufferevent, EV_READ, (*pbuf)->size, (*pbuf)->size);
    }
    else
    {
        if (bufferevent_read(desc->mitm_bufferevent, (*pbuf)->buf, (*pbuf)->size) != (*pbuf)->size)
        {
            mitm_rs_error(desc);
            return;
        }

        bufferedWrite(desc, FDMITM, *pbuf);
        *pbuf = NULL;
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
        if(desc->first_mitm_connection)
        {
            /* the first time a socket is attached, a struct with the collected infos
             * is sent to the client, for this reason the banner is put on the head of
             * the configuration struct.
             *
             * Why has been done ? 
             * because, will happen too often to telnet to a local port. it's a nice to get info :)
             */
            write(desc->fd[FDMITM], (void *)&conf, sizeof(conf));
            desc->first_mitm_connection = 0;
        }
    
        event_del(&desc->ev_recv[FDMITMATTACH]);
        setfdflag(desc->fd[FDMITM], FD_CLOEXEC);
        setflflag(desc->fd[FDMITM], O_NONBLOCK);
    }
    else
    {
        if (errno != EAGAIN)
            event_loopbreak();
    }

    desc->mitm_bufferevent = bufferevent_new(desc->fd[FDMITM], mitmrecv_cb, NULL, mitm_rs_error_cb, desc);
    bufferevent_setwatermark(desc->mitm_bufferevent, EV_READ, 2, 2);
    bufferevent_enable(desc->mitm_bufferevent, EV_READ);
}

static uint8_t setupNET(void)
{
    int net = -1;

    char ebuf[PCAP_ERRBUF_SIZE];

    capnet = pcap_open_live(get_sysmap_str('2'), 65535, 0, 0, ebuf);
    if (capnet == NULL)
        runtime_exception("unable to open pcap handle on interface %s: %s ", get_sysmap_str('2'), ebuf);

    net = pcap_fileno(capnet);

    setfdflag(net, FD_CLOEXEC);

    if (pcap_setnonblock(capnet, 1, ebuf) == -1)
        runtime_exception("unable to set pcap handle in non blocking mode on interface %s", get_sysmap_str('2'));

    return net;
}

static uint8_t setupTUN(void)
{
    static char tun_name[10];

    int tun;

    if(( tun = tun_open(tun_name, 10)) == -1)
        runtime_exception("unable to open tun interface: %s: %s", tun_name, strerror(errno));

    map_external_str('T', tun_name);

    sysmap_command('B');

    setfdflag(tun, FD_CLOEXEC);

    return tun;
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

/* 
 * in janus bootstrap the first and the second sections of the configuration commands
 * are executed
 */
void JANUS_Bootstrap(void)
{
    uint8_t i, j;

    janus_commands_file_setup(fopen(OSSELECTED, "r"));

    map_external_str('K', get_sysmap_str('4'));

    /* now we had the commands stored and the infos detected */
    /* execute "informative" commands (second section in the commands file) */

    /* MTU, handle the variable called "K", instanced after this fix */
    janus_conf_MTUfix(conf.mtu_fix);

    capnet = NULL;

    /* acquire mac address inside the ethernet struct */
    parseMAC(get_sysmap_str('6'), netif_send_hdr.dst_ethernet);
    parseMAC(get_sysmap_str('5'), netif_send_hdr.src_ethernet);

    memcpy(netif_recv_hdr.dst_ethernet, netif_send_hdr.src_ethernet, ETH_ALEN);
    memcpy(netif_recv_hdr.src_ethernet, netif_send_hdr.dst_ethernet, ETH_ALEN);

    netif_send_hdr.link_type = netif_recv_hdr.link_type = htons(ETH_P_IP);

    /* this command: get_sysmap_str('K'), will return a runtime exception if was not
     * initialized by janus_conf_MTUfix */
    pbuf_len = atoi(get_sysmap_str('K'));

    pbufs = pbufs_malloc(conf.pqueue_len, pbuf_len);

    J_MALLOC(macpkt, pbuf_len);

    memcpy(macpkt, &netif_send_hdr, ETH_HLEN);

    memset(&mitm_desc, 0, sizeof (mitm_desc));

    mitm_desc[NET].fd_recv = netif_recv;
    mitm_desc[NET].fd_send = netif_send;
    mitm_desc[TUN].fd_recv = tunif_recv;
    mitm_desc[TUN].fd_send = tunif_send;

    for (i = 0; i < 2; ++i)
    {
        mitm_desc[i].pqueue = queue_malloc(pbufs);

        for (j = 0; j < 3; ++j)
            mitm_desc[i].fd[j] = -1;

        mitm_desc[i].first_mitm_connection = 1;
    }
}

void JANUS_Init(void)
{
    ev_base = event_init();

    mitm_desc[NET].fd[FDIF] = setupNET();
    mitm_desc[NET].fd[FDMITMATTACH] = setupMitmAttach(conf.listen_port_in);
    mitm_desc[NET].target = &mitm_desc[TUN];

    mitm_desc[TUN].fd[FDIF] = setupTUN();
    mitm_desc[TUN].fd[FDMITMATTACH] = setupMitmAttach(conf.listen_port_out);
    mitm_desc[TUN].target = &mitm_desc[NET];

    /* ;E delete the system default gateway */
    sysmap_command('E');

    /* ;7 add a default gateway */
    sysmap_command('7');
 
    /* ;9 add a firewall rules able to drop incoming traffic with src mac addr $5 */
    sysmap_command('9');

    /* ;C add a firewall rule able to NAT the traffic through the tunnel */
    sysmap_command('C');
}

void JANUS_EventLoop(void)
{
    uint8_t i;

    ev_base = event_init();

    for (i = 0; i < 2; ++i)
    {
        event_set(&mitm_desc[i].ev_send, mitm_desc[i].fd[FDIF], EV_WRITE | EV_PERSIST, send_cb, &mitm_desc[i]);
        event_set(&mitm_desc[i].ev_recv[FDIF], mitm_desc[i].fd[FDIF], EV_READ | EV_PERSIST, recv_cb, &mitm_desc[i]);
        event_set(&mitm_desc[i].ev_recv[FDMITMATTACH], mitm_desc[i].fd[FDMITMATTACH], EV_READ, mitmattach_cb, &mitm_desc[i]);

        event_add(&mitm_desc[i].ev_recv[FDIF], NULL);
        event_add(&mitm_desc[i].ev_recv[FDMITMATTACH], NULL);
    }

    event_dispatch();
}

void JANUS_Reset(void)
{
    uint8_t i, j;

    /* ;8 delete the janus-fake default gateway */
    sysmap_command('8');

    /* ;G restore the system default gateway */
    sysmap_command('G');

    /* ;D delete the firewall rule insert with $C */
    sysmap_command('D');

    /* ;A delete the firewall rules insert with $9 */
    sysmap_command('A');

    J_PCAP_CLOSE(&capnet);

    for (i = 0; i < 2; ++i)
    {
        queue_reset(mitm_desc[i].pqueue);

        J_PBUF_RELEASE(&mitm_desc[i].pbuf_send);

        J_BUFFEREVENT_FREE(&mitm_desc[i].mitm_bufferevent);

        for (j = 0; j < 3; ++j)
        {
            if (j < 2)
                J_PBUF_RELEASE(&mitm_desc[i].pbuf_recv[j]);

            J_CLOSE(&mitm_desc[i].fd[j]);
        }

        mitm_desc[i].first_mitm_connection = 1;
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
