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
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <event.h>
#include <pcap.h>

#include "janus.h"
#include "packet_queue.h"

enum mitm_t
{
    NET = 0,
    TUN = 1,
    NETMITM = 2,
    TUNMITM = 3,
    NETMITMATTACH = 4,
    TUNMITMATTACH = 5
};

struct janus_config conf;

static struct packets *pkts = NULL;

static pcap_t *capnet = NULL;
static char *macpkt = NULL;
static char ebuf[PCAP_ERRBUF_SIZE];

static char net_if_str[CONST_JANUS_BUFSIZE] = {0};
static char net_ip_str[CONST_JANUS_BUFSIZE] = {0};
static char tun_if_str[CONST_JANUS_BUFSIZE] = {0};
static char tun_ip_str[CONST_JANUS_BUFSIZE] = {0};
static char gw_mac_str[CONST_JANUS_BUFSIZE] = {0};
static char gw_ip_str[CONST_JANUS_BUFSIZE] = {0};

static char net_mtu_str[CONST_JANUS_BUFSIZE] = {0};
static uint16_t mtu;

static uint8_t netif_recv_hdr[ETH_HLEN] = {0};
static uint8_t netif_send_hdr[ETH_HLEN] = {0};

static uint8_t gw_mac[ETH_ALEN] = {0};

static int fd[6] = {-1};
static struct event ev_recv[6];
static struct event ev_send[6];
static enum mitm_t handler_index[6];

static ssize_t(*fd_recv[4])();
static ssize_t(*fd_send[4])();
static struct packet *pbuf_recv[4] = {NULL};
static struct packet *pbuf_send[4] = {NULL};
static struct packet_queue *pqueue[2] = {NULL};

static struct bufferevent* mitm_bufferevent[2] = {NULL};

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

static int32_t bufferedRead(enum mitm_t i)
{
    return queue_pop_front(pqueue[i], &pbuf_send[i]);
}

static void bufferedWrite(enum mitm_t i)
{
    struct packet *pkt = pbuf_recv[i];
    pbuf_recv[i] = NULL;

    switch (i)
    {
    case NET:
        i = (fd[NETMITM] == -1) ? TUN : NETMITM;
        break;
    case TUN:
        i = (fd[TUNMITM] == -1) ? NET : TUNMITM;
        break;
    case NETMITM:
        i = TUN;
        break;
    case TUNMITM:
        i = NET;
        break;
    default:
        printf("!? [%s:%u]: %u", __func__, __LINE__, i);
        raise(SIGTERM);
        return;
    }

    if ((i == TUN) || (i == NET))
    {
        if (pqueue[i]->count == 0)
            event_add(&ev_send[i], NULL);

        queue_push_back(pqueue[i], pkt);
    }
    else
    {
        uint16_t size = htons(pkt->size);
        i = (i == NETMITM) ? 0 : 1;
        bufferevent_write(mitm_bufferevent[i], &size, sizeof (size));
        bufferevent_write(mitm_bufferevent[i], pkt->buf, pkt->size);
        pbuf_release(pkts, pkt);
    }
}

static void mitm_rs_error(enum mitm_t i)
{
    uint8_t j = (i == NETMITM) ? 0 : 1;

    event_del(&ev_recv[i]);
    event_del(&ev_send[i]);

    close(fd[i]);
    fd[i] = -1;

    if (mitm_bufferevent[j] != NULL)
    {
        bufferevent_free(mitm_bufferevent[j]);
        mitm_bufferevent[j] = NULL;
    }

    event_add(&ev_recv[(i == NETMITM) ? NETMITMATTACH : TUNMITMATTACH], NULL);
}

static void mitm_attach(uint8_t i, uint8_t j)
{
    fd[j] = accept(fd[i], NULL, NULL);
    if (fd[j] != -1)
    {
        event_del(&ev_recv[i]);
        setfdflag(fd[j], FD_CLOEXEC);
        setflflag(fd[j], O_NONBLOCK);
    }
    else
    {
        if (errno != EAGAIN)
            event_loopbreak();
    }
}

static ssize_t netif_recv(void)
{
    struct pcap_pkthdr header;
    const u_char *packet = pcap_next(capnet, &header);

    if ((packet != NULL) && !memcmp(packet, netif_recv_hdr, ETH_HLEN))
    {
        uint32_t len = header.len - ETH_HLEN;
        len = (len > mtu) ? mtu : len;
        memcpy(pbuf_recv[NET]->buf, packet + ETH_HLEN, len);
        return header.len - ETH_HLEN;
    }
    else
    {
        errno = EAGAIN;
        return -1;
    }
}

static ssize_t netif_send(void)
{
    memcpy(&macpkt[ETH_HLEN], pbuf_send[NET]->buf, pbuf_send[NET]->size);

    if (pcap_inject(capnet, macpkt, ETH_HLEN + pbuf_send[NET]->size) != -1)
        return pbuf_send[NET]->size;
    else
        return -1;
}

static ssize_t tunif_recv(void)
{
    return read(fd[TUN], pbuf_recv[TUN]->buf, mtu);
}

static ssize_t tunif_send(void)
{
    return write(fd[TUN], pbuf_send[TUN]->buf, pbuf_send[TUN]->size);
}

static void recv_cb(int f, short event, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;

    if ((pbuf_recv[i] != NULL) || ((pbuf_recv[i] = pbuf_acquire(pkts)) != NULL))
    {
        ssize_t ret = fd_recv[i]();

        if (ret > 0)
        {
            pbuf_recv[i]->size = ret;
            bufferedWrite(i);
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
    const enum mitm_t i = *(enum mitm_t *) arg;

    if (pbuf_send[i] != NULL || (bufferedRead(i) != -1))
    {
        const ssize_t ret = fd_send[i]();

        if (ret == pbuf_send[i]->size)
        {
            pbuf_release(pkts, pbuf_send[i]);
            pbuf_send[i] = NULL;

            if (pqueue[i]->count == 0)
                event_del(&ev_send[i]);
        }
        else
        {
            if (errno != EAGAIN)
                event_loopbreak();
        }
    }
}

static void mitm_rs_error_cb(struct bufferevent *sabe, short what, void *arg)
{
    mitm_rs_error(*(enum mitm_t *) arg);
}

static void mitmrecv_cb(struct bufferevent *sabe, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;
    const uint8_t k = (i == NETMITM) ? 0 : 1;

    if (pbuf_recv[i] == NULL)
    {
        pbuf_recv[i] = pbuf_acquire(pkts);
        if (pbuf_recv[i] == NULL)
            return;

        if (bufferevent_read(mitm_bufferevent[k], &pbuf_recv[i]->size, sizeof (uint16_t)) != sizeof (uint16_t))
        {
            mitm_rs_error(i);
            return;
        }

        pbuf_recv[i]->size = ntohs(pbuf_recv[i]->size);
        bufferevent_setwatermark(mitm_bufferevent[k], EV_READ, pbuf_recv[i]->size, pbuf_recv[i]->size);
    }
    else
    {
        if (bufferevent_read(mitm_bufferevent[k], pbuf_recv[i]->buf, pbuf_recv[i]->size) != pbuf_recv[i]->size)
        {
            mitm_rs_error(i);
            return;
        }

        bufferedWrite(i);
        bufferevent_setwatermark(mitm_bufferevent[k], EV_READ, sizeof (uint16_t), sizeof (uint16_t));

    }
}

static void mitmattach_cb(int f, short event, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;

    const enum mitm_t j = (i == NETMITMATTACH) ? NETMITM : TUNMITM;
    const uint8_t k = (j == NETMITM) ? 0 : 1;

    mitm_attach(i, j);

    mitm_bufferevent[k] = bufferevent_new(fd[j], mitmrecv_cb, NULL, mitm_rs_error_cb, &handler_index[j]);
    bufferevent_setwatermark(mitm_bufferevent[k], EV_READ, 2, 2);
    bufferevent_enable(mitm_bufferevent[k], EV_READ);
}

static uint8_t setupNET(void)
{
    struct ifreq tmpifr;
    int tmpfd;

    int net = -1;

    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    memset(&tmpifr, 0x00, sizeof (tmpifr));
    strncpy(tmpifr.ifr_name, net_if_str, sizeof (tmpifr.ifr_name));
    if (ioctl(tmpfd, SIOCGIFINDEX, &tmpifr) == -1)
        runtime_exception("unable to execute ioctl(SIOCGIFINDEX) on interface %s", net_if_str);

    if (ioctl(tmpfd, SIOCGIFHWADDR, &tmpifr) == -1)
        runtime_exception("unable to execute ioctl(SIOCGIFHWADDR) on interface %s", net_if_str);

    memcpy(netif_send_hdr, gw_mac, ETH_ALEN);
    memcpy(&netif_send_hdr[ETH_ALEN], tmpifr.ifr_hwaddr.sa_data, ETH_ALEN);
    *(uint16_t *)&netif_send_hdr[2 * ETH_ALEN] = htons(ETH_P_IP);

    memcpy(netif_recv_hdr, tmpifr.ifr_hwaddr.sa_data, ETH_ALEN);
    memcpy(&netif_recv_hdr[ETH_ALEN], gw_mac, ETH_ALEN);
    *(uint16_t *)&netif_recv_hdr[2 * ETH_ALEN] = htons(ETH_P_IP);

    memcpy(macpkt, netif_send_hdr, ETH_HLEN);

    close(tmpfd);

    capnet = pcap_open_live(net_if_str, 65535, 0, -1, ebuf);
    if (capnet == NULL)
        runtime_exception("unable to open pcap handle on interface %s", net_if_str);

    if (pcap_setnonblock(capnet, 1, ebuf) == -1)
        runtime_exception("unable to set pcap handle in non blocking mode on interface %s", net_if_str);

    net = pcap_fileno(capnet);

    setfdflag(net, FD_CLOEXEC);

    return net;
}

static uint8_t setupTUN(void)
{
    const char *tundev = "/dev/net/tun";

    struct ifreq tmpifr;
    struct sockaddr_in *ssa = (struct sockaddr_in *) &tmpifr.ifr_addr;
    int tmpfd;
    int i;

    int tun = open(tundev, O_RDWR);
    if (tun == -1)
        runtime_exception("unable to open %s", tundev);

    memset(&tmpifr, 0x00, sizeof (tmpifr));
    tmpifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    for (i = 0; i < 64; ++i)
    {
        snprintf(tmpifr.ifr_name, sizeof (tmpifr.ifr_name), "%s%u", CONST_JANUS_IFNAME, i);
        if (!ioctl(tun, TUNSETIFF, &tmpifr))
            break;

        if (i == 63)
            runtime_exception("unable to set tun flags (TUNSETIFF)");
    }

    snprintf(tun_if_str, sizeof (tun_if_str), "%s", tmpifr.ifr_name);
    snprintf(tun_ip_str, sizeof (tun_ip_str), "%s%u", CONST_JANUS_FAKEGW_IP, i + 1);

    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (ioctl(tmpfd, SIOCGIFFLAGS, &tmpifr) == -1)
        runtime_exception("unable to get tun flags (SIOCGIFFLAGS)");

    tmpifr.ifr_flags |= IFF_UP | IFF_RUNNING | IFF_POINTOPOINT;

    if (ioctl(tmpfd, SIOCSIFFLAGS, &tmpifr) == -1)
        runtime_exception("unable to set tun flags (SIOCSIFFLAGS)");

    tmpifr.ifr_mtu = mtu;
    if (ioctl(tmpfd, SIOCSIFMTU, &tmpifr) == -1)
        runtime_exception("unable to set tun mtu (SIOCSIFMTU)");

    ssa->sin_family = AF_INET;
    ssa->sin_addr.s_addr = inet_addr(net_ip_str);
    if (ioctl(tmpfd, SIOCSIFADDR, &tmpifr) == -1)
        runtime_exception("unable to set tun local addr to %s", net_ip_str);

    ssa->sin_family = AF_INET;
    ssa->sin_addr.s_addr = inet_addr(tun_ip_str);
    if (ioctl(tmpfd, SIOCSIFDSTADDR, &tmpifr) == -1)
        runtime_exception("unable to set tun point-to-point dest addr to %s", tun_ip_str);

    close(tmpfd);

    setfdflag(tun, FD_CLOEXEC);
    setflflag(tun, O_NONBLOCK);

    return tun;
}

static int setupMitmAttach(uint16_t port)
{
    int fd = -1;
    int on = 1;
    struct sockaddr_in ssin;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        runtime_exception("unable to open socket");

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (int));

    memset(&ssin, 0, sizeof (struct sockaddr_in));
    ssin.sin_family = AF_INET;
    ssin.sin_port = htons(port);
    if (!inet_aton(conf.listen_ip, (struct in_addr *) &ssin.sin_addr.s_addr))
        runtime_exception("invalid listening address provided");

    if (bind(fd, (struct sockaddr *) &ssin, sizeof (struct sockaddr_in)) < 0)
        runtime_exception("unable to bind");

    if (listen(fd, 0) < 0)
        runtime_exception("unable to listen");

    return fd;
}

uint8_t JANUS_Bootstrap(void)
{
    unsigned int mac[ETH_ALEN];

    uint8_t i;

    bindCmds();

    cmd[0](net_if_str, sizeof (net_if_str));
    if (!strlen(net_if_str))
        runtime_exception("unable to detect default gateway interface");

    printf("detected default gateway interface: [%s]\n", net_if_str);

    cmd[1](net_ip_str, sizeof (net_ip_str));
    if (!strlen(net_ip_str))
        runtime_exception("unable to detect ", net_if_str, " ip address");

    printf("detected local ip address on interface %s: [%s]\n", net_if_str, net_ip_str);

    cmd[2](net_mtu_str, sizeof (net_mtu_str));
    if (!strlen(net_mtu_str))
        runtime_exception("unable to detect default gateway mtu");

    mtu = atoi(net_mtu_str);

    printf("detected default gateway MTU: [%s]\n", net_mtu_str);

    cmd[3](gw_ip_str, sizeof (gw_ip_str));
    if (!strlen(gw_ip_str))
        runtime_exception("unable to detect default gateway ip address");

    printf("detected default gateway ip address: [%s]\n", gw_ip_str);

    cmd[4](gw_mac_str, sizeof (gw_mac_str));
    if (!strlen(gw_mac_str))
        runtime_exception("unable to detect default gateway mac address");

    sscanf(gw_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    for (i = 0; i < ETH_ALEN; ++i)
        gw_mac[i] = mac[i];

    printf("detected default gateway mac address: [%s]\n", gw_mac_str);

    pkts = pbufs_malloc(conf.pqueue_len, mtu);
    if (pkts == NULL)
        runtime_exception("unable to allocate memory for packet buffers");

    for (i = 0; i < 6; ++i)
    {
        if (i < 2)
        {
            pqueue[i] = queue_malloc(pkts);
            if (pqueue[i] == NULL)
                runtime_exception("unable to allocate memory for packet queues");
        }

        handler_index[i] = (enum mitm_t)i;
    }

    macpkt = malloc(ETH_HLEN + mtu);
    if (macpkt == NULL)
        runtime_exception("unable to allocate memory for the datalink packet buffer");

    fd_recv[NET] = netif_recv;
    fd_send[NET] = netif_send;
    fd_recv[TUN] = tunif_recv;
    fd_send[TUN] = tunif_send;

    return 0;
}

uint8_t JANUS_Init(void)
{
    uint8_t i;

    fd[NET] = setupNET();
    fd[TUN] = setupTUN();
    fd[NETMITM] = -1;
    fd[TUNMITM] = -1;
    fd[NETMITMATTACH] = setupMitmAttach(conf.listen_port_in);
    fd[TUNMITMATTACH] = setupMitmAttach(conf.listen_port_out);

    for (i = 5; i < 10; ++i)
        cmd[i](NULL, 0);

    return 0;
}

void JANUS_EventLoop(void)
{
    struct event_base *ev_base = event_init();

    event_set(&ev_send[NET], fd[NET], EV_WRITE | EV_PERSIST, send_cb, &handler_index[NET]);
    event_set(&ev_send[TUN], fd[TUN], EV_WRITE | EV_PERSIST, send_cb, &handler_index[TUN]);
    event_set(&ev_recv[NET], fd[NET], EV_READ | EV_PERSIST, recv_cb, &handler_index[NET]);
    event_set(&ev_recv[TUN], fd[TUN], EV_READ | EV_PERSIST, recv_cb, &handler_index[TUN]);
    event_set(&ev_recv[NETMITMATTACH], fd[NETMITMATTACH], EV_READ, mitmattach_cb, &handler_index[NETMITMATTACH]);
    event_set(&ev_recv[TUNMITMATTACH], fd[TUNMITMATTACH], EV_READ, mitmattach_cb, &handler_index[TUNMITMATTACH]);

    event_add(&ev_recv[NET], NULL);
    event_add(&ev_recv[TUN], NULL);
    event_add(&ev_recv[NETMITMATTACH], NULL);
    event_add(&ev_recv[TUNMITMATTACH], NULL);

    event_dispatch();

    event_base_free(ev_base);
}

uint8_t JANUS_Reset(void)
{
    uint8_t i;

    for (i = 10; i < 15; ++i)
        cmd[i](NULL, 0);

    if (capnet != NULL)
    {
        pcap_close(capnet);
        capnet = NULL;
    }

    for (i = 0; i < 6; ++i)
    {
        if (i < 2)
        {
            queue_reset(pqueue[i]);

            if (mitm_bufferevent[i] != NULL)
            {
                bufferevent_free(mitm_bufferevent[i]);
                mitm_bufferevent[i] = NULL;
            }
        }

        if (fd[i] != -1)
        {
            close(fd[i]);
            fd[i] = -1;
        }
    }

    return 0;
}

uint8_t JANUS_Shutdown(void)
{
    uint8_t i;

    free(macpkt);

    for (i = 0; i < 2; ++i)
        queue_free(pqueue[i]);

    pbufs_free(pkts);

    return 0;
}
