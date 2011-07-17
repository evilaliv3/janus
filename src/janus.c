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
#include "config_macros.h"
#include "packet_queue.h"

#ifndef ETH_HLEN
#define ETH_HLEN              14
#endif

#ifndef ETH_ALEN
#define ETH_ALEN              6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP              0x0800
#endif

#define J_CLOSE(p)            if (*p != -1) { close(*p); *p = -1; }
#define J_PCAP_CLOSE(p)       if (*p != NULL) { pcap_close(*p); *p = NULL; }
#define J_BUFFEREVENT_FREE(p) if (*p != NULL) { bufferevent_free(*p); *p = NULL; }
#define J_PBUF_RELEASE(p)     if (*p != NULL) { *p = NULL; }

#define NET                   0
#define TUN                   1

enum mitm_t
{
    FDIF = 0,
    FDMITM = 1,
    FDMITMATTACH = 2
};

struct janus_config conf;

static struct packets *pbufs;

static pcap_t *capnet;
static char *macpkt;

static char str[STRINGS_NUM][CONST_JANUS_BUFSIZE];

static uint8_t netif_send_hdr[ETH_HLEN];
static uint8_t netif_recv_hdr[ETH_HLEN];

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
};

static struct mitm_descriptor mitm_desc[2];

static void runtime_exception(const char *format, ...)
{
    char error[CONST_JANUS_BUFSIZE] = {0};

    va_list arguments;
    va_start(arguments, format);
    vsnprintf(error, sizeof (error), format, arguments);
    va_end(arguments);

    printf("runtime exception: %s\n", error);
    exit(1);
}

#include "os_cmds.c"

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

static struct packet* bufferedRead(struct mitm_descriptor* desc)
{
    return queue_pop_front(desc->pqueue, &desc->pbuf_send);
}

static void bufferedWrite(struct mitm_descriptor* desc, enum mitm_t i, struct packet *pbuf)
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

static ssize_t netif_recv(int sockfd, struct packet* pbuf)
{
    struct pcap_pkthdr header;
    const u_char * const packet = pcap_next(capnet, &header);

    if ((packet != NULL) && !memcmp(packet, netif_recv_hdr, ETH_HLEN))
    {
        uint16_t mtu = atoi(str[STR_NET_MTU]);
        uint32_t len = header.len - ETH_HLEN;
        len = (len > mtu) ? mtu : len;
        memcpy(pbuf->buf, packet + ETH_HLEN, len);
        return header.len - ETH_HLEN;
    }

    errno = EAGAIN;
    return -1;
}

static ssize_t netif_send(int sockfd, struct packet* pbuf)
{
    memcpy(&macpkt[ETH_HLEN], pbuf->buf, pbuf->size);

    if (pcap_inject(capnet, macpkt, ETH_HLEN + pbuf->size) != -1)
        return pbuf->size;
    else
        return -1;
}

static ssize_t tunif_recv(int sockfd, struct packet* pbuf)
{
    return read(sockfd, pbuf->buf, atoi(str[STR_NET_MTU]));
}

static ssize_t tunif_send(int sockfd, struct packet* pbuf)
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

    capnet = pcap_open_live(str[STR_NET_IF], 65535, 0, -1, ebuf);
    if (capnet == NULL)
        runtime_exception("unable to open pcap handle on interface %s", str[STR_NET_IF]);

    net = pcap_fileno(capnet);

    setfdflag(net, FD_CLOEXEC);

    if (pcap_setnonblock(capnet, 1, ebuf) == -1)
        runtime_exception("unable to set pcap handle in non blocking mode on interface %s", str[STR_NET_IF]);

    return net;
}

static uint8_t setupTUN(void)
{
    int tun = tun_open(str[STR_TUN_IF], sizeof (str[STR_TUN_IF]));
    if (tun == -1)
        runtime_exception("unable to open tun interface");

    snprintf(str[STR_TUN_IP], sizeof (str[STR_TUN_IP]), CONST_JANUS_FAKEGW_IP);

    cmd[CMD_SETUP_TUN](NULL, 0);

    setfdflag(tun, FD_CLOEXEC);
    setflflag(tun, O_NONBLOCK);

    return tun;
}

static int setupMitmAttach(uint16_t port)
{
    int fd = -1;

    struct sockaddr_in ssin;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        runtime_exception("unable to open socket");

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

void JANUS_Bootstrap(void)
{
    uint8_t mac[ETH_ALEN];
    uint32_t tmp_mac[ETH_ALEN];

    uint8_t i, j;

    for (i = 0; i < STRINGS_NUM; i++)
        str[i][0] = '\0';

    bindCmds();

    cmd[CMD_GET_NETIF](str[STR_NET_IF], sizeof (str[STR_NET_IF]));
    if (!strlen(str[STR_NET_IF]))
        runtime_exception("unable to detect default gateway interface");

    printf("detected default gateway interface: [%s]\n", str[STR_NET_IF]);

    cmd[CMD_GET_NETIP](str[STR_NET_IP], sizeof (str[STR_NET_IP]));
    if (!strlen(str[STR_NET_IP]))
        runtime_exception("unable to detect ", str[STR_NET_IF], " ip address");

    printf("detected local ip address on interface %s: [%s]\n", str[STR_NET_IF], str[STR_NET_IP]);

    cmd[CMD_GET_NETMAC](str[STR_NET_MAC], sizeof (str[STR_NET_MAC]));
    if (!strlen(str[STR_NET_MAC]))
        runtime_exception("unable to detect ", str[STR_NET_IF], " mac address");

    printf("detected local mac address on interface %s: [%s]\n", str[STR_NET_IF], str[STR_NET_MAC]);

    cmd[CMD_GET_NETMTU](str[STR_NET_MTU], sizeof (str[STR_NET_MTU]));
    if (!strlen(str[STR_NET_MTU]))
        runtime_exception("unable to detect", str[STR_NET_IF], " mtu");

    printf("detected default gateway MTU: [%s]\n", str[STR_NET_MTU]);

    cmd[CMD_GET_GWIP](str[STR_GW_IP], sizeof (str[STR_GW_IP]));
    if (!strlen(str[STR_GW_IP]))
        runtime_exception("unable to detect default gateway ip address");

    printf("detected default gateway ip address: [%s]\n", str[STR_GW_IP]);

    cmd[CMD_GET_GWMAC](str[STR_GW_MAC], sizeof (str[STR_GW_MAC]));
    if (!strlen(str[STR_GW_MAC]))
        runtime_exception("unable to detect default gateway mac address");

    printf("detected default gateway mac address: [%s]\n", str[STR_GW_MAC]);

    capnet = NULL;

    sscanf(str[STR_NET_MAC], "%02x:%02x:%02x:%02x:%02x:%02x", &tmp_mac[0], &tmp_mac[1], &tmp_mac[2], &tmp_mac[3], &tmp_mac[4], &tmp_mac[5]);
    for (i = 0; i < ETH_ALEN; ++i)
        mac[i] = tmp_mac[i];

    memcpy(netif_recv_hdr, mac, ETH_ALEN);
    memcpy(&netif_send_hdr[ETH_ALEN], mac, ETH_ALEN);

    sscanf(str[STR_GW_MAC], "%02x:%02x:%02x:%02x:%02x:%02x", &tmp_mac[0], &tmp_mac[1], &tmp_mac[2], &tmp_mac[3], &tmp_mac[4], &tmp_mac[5]);
    for (i = 0; i < ETH_ALEN; ++i)
        mac[i] = tmp_mac[i];

    memcpy(netif_send_hdr, mac, ETH_ALEN);
    memcpy(&netif_recv_hdr[ETH_ALEN], mac, ETH_ALEN);

    memcpy(macpkt, netif_send_hdr, ETH_HLEN);

    macpkt = malloc(ETH_HLEN + atoi(str[STR_NET_MTU]));
    if (macpkt == NULL)
        runtime_exception("unable to allocate memory for the datalink packet buffer");

    pbufs = pbufs_malloc(conf.pqueue_len, atoi(str[STR_NET_MTU]));
    if (pbufs == NULL)
        runtime_exception("unable to allocate memory for packet buffers");

    memset(&mitm_desc, 0, sizeof (mitm_desc));

    mitm_desc[NET].fd_recv = netif_recv;
    mitm_desc[NET].fd_send = netif_send;
    mitm_desc[TUN].fd_recv = tunif_recv;
    mitm_desc[TUN].fd_send = tunif_send;

    for (i = 0; i < 2; ++i)
    {
        mitm_desc[i].pqueue = queue_malloc(pbufs);
        if (mitm_desc[i].pqueue == NULL)
            runtime_exception("unable to allocate memory for packet queues");

        for (j = 0; j < 3; ++j)
            mitm_desc[i].fd[j] = -1;
    }
}

void JANUS_Init(void)
{
    mitm_desc[NET].fd[FDIF] = setupNET();
    mitm_desc[NET].fd[FDMITMATTACH] = setupMitmAttach(conf.listen_port_in);
    mitm_desc[NET].target = &mitm_desc[TUN];

    mitm_desc[TUN].fd[FDIF] = setupTUN();
    mitm_desc[TUN].fd[FDMITMATTACH] = setupMitmAttach(conf.listen_port_out);
    mitm_desc[TUN].target = &mitm_desc[NET];

    cmd[CMD_DEL_REAL_DEFAULT_ROUTE](NULL, 0);
    cmd[CMD_ADD_FAKE_DEFAULT_ROUTE](NULL, 0);
    cmd[CMD_ADD_INCOMING_FILTER](NULL, 0);
    cmd[CMD_ADD_FORWARD_FILTER](NULL, 0);
    cmd[CMD_ADD_TUN_MASQUERADE](NULL, 0);
}

void JANUS_EventLoop(void)
{
    struct event_base * const ev_base = event_init();

    uint8_t i;

    for (i = 0; i < 2; ++i)
    {
        event_set(&mitm_desc[i].ev_send, mitm_desc[i].fd[FDIF], EV_WRITE | EV_PERSIST, send_cb, &mitm_desc[i]);
        event_set(&mitm_desc[i].ev_recv[FDIF], mitm_desc[i].fd[FDIF], EV_READ | EV_PERSIST, recv_cb, &mitm_desc[i]);
        event_set(&mitm_desc[i].ev_recv[FDMITMATTACH], mitm_desc[i].fd[FDMITMATTACH], EV_READ, mitmattach_cb, &mitm_desc[i]);

        event_add(&mitm_desc[i].ev_recv[FDIF], NULL);
        event_add(&mitm_desc[i].ev_recv[FDMITMATTACH], NULL);
    }

    event_dispatch();

    event_base_free(ev_base);
}

void JANUS_Reset(void)
{
    uint8_t i, j;

    cmd[CMD_DEL_FAKE_DEFAULT_ROUTE](NULL, 0);
    cmd[CMD_ADD_REAL_DEFAULT_ROUTE](NULL, 0);
    cmd[CMD_DEL_INCOMING_FILTER](NULL, 0);
    cmd[CMD_DEL_FORWARD_FILTER](NULL, 0);
    cmd[CMD_DEL_TUN_MASQUERADE](NULL, 0);

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
    }
}

void JANUS_Shutdown(void)
{
    uint8_t i;

    for (i = 0; i < 2; ++i)
        queue_free(mitm_desc[i].pqueue);

    pbufs_free(pbufs);

    free(macpkt);
}
