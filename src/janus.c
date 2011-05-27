/*
 * Janus, a portable, unified and lightweight interface for mitm
 * applications over the routing table.
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

#include "errno.h"
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
#include <netpacket/packet.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <event.h>

#include "janus.h"
#include "packet_queue.h"

enum mitm_t
{
    NET = 0, TUN = 1, NETMITM = 2, TUNMITM = 3, NETMITMATTACH = 4, TUNMITMATTACH = 5
};

struct janus_config conf;

static char net_if[CONST_JANUS_BUFSIZE] = {0};
static char net_ip[CONST_JANUS_BUFSIZE] = {0};
static char tun_if[CONST_JANUS_BUFSIZE] = {0};
static char tun_ip[CONST_JANUS_BUFSIZE] = {0};
static char gw_ip[CONST_JANUS_BUFSIZE] = {0};
static char gw_mac[CONST_JANUS_BUFSIZE] = {0};
static uint16_t mtu;

static struct sockaddr_ll gw_send_ll;

static int fd[6] = {-1};
static struct event ev_recv[6];
static struct event ev_send[6];
static enum mitm_t handler_index[6];

static size_t(*fd_recv[4])(const struct packet *);
static size_t(*fd_send[4])(const struct packet *);
static struct packet *pbuf_recv[4] = {NULL};
static struct packet *pbuf_send[4] = {NULL};
static struct packet_queue pqueue[4];

static void runtime_exception(const char* format, ...)
{
    char error[CONST_JANUS_BUFSIZE] = {0};

    va_list arguments;
    va_start(arguments, format);
    vsnprintf(error, sizeof (error), format, arguments);
    va_end(arguments);

    printf("runtime exception: %s\n", error);
    exit(1);
}

static void execOSCmd(char* buf, size_t bufsize, const char* format, ...)
{
    char cmd[CONST_JANUS_BUFSIZE] = {0};
    FILE *stream = NULL;

    va_list arguments;
    va_start(arguments, format);
    vsnprintf(cmd, sizeof (cmd), format, arguments);
    va_end(arguments);

    printf("executing cmd: [%s]\n", cmd);

    stream = popen(cmd, "r");
    if (stream != NULL)
    {
        if (buf != NULL)
        {
            if (fgets(buf, bufsize, stream) != NULL)
            {
                size_t len = strlen(buf);

                if (len && buf[len - 1] == '\n')
                    buf[len - 1] = '\0';
            }
        }

        pclose(stream);
    }
}

static void setfdflag(int fd, long flags)
{
    long tmpflags;
    if (((tmpflags = fcntl(fd, F_GETFD)) == -1) || (fcntl(fd, F_SETFD, tmpflags | flags) == -1))
        runtime_exception("unable to set flags %u on fd %u (F_GETFD/F_SETFD): %s", flags, fd);
}

static struct packet* bufferedRead(enum mitm_t i)
{
    return queue_extract(&pqueue[i]);
}

static void bufferedWrite(enum mitm_t i, struct packet * pkt)
{
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

    queue_insert(&pqueue[i], pkt);
    event_add(&ev_send[i], NULL);
}

static void resetState(uint8_t i)
{
    free_packet(&pbuf_recv[i]);
    free_packet(&pbuf_send[i]);
}

static void mitm_attach(uint8_t i, uint8_t j)
{
    fd[j] = accept(fd[i], NULL, NULL);
    if (fd[j] != -1)
    {
        setfdflag(fd[j], FD_CLOEXEC | O_NONBLOCK);
    }
    else
    {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
            event_loopbreak();
    }
}

static size_t netif_recv(const struct packet* pkt)
{
    struct sockaddr_ll from_ll;
    socklen_t fromlen = sizeof (struct sockaddr_ll);

    const size_t ret = recvfrom(fd[NET], pkt->buf, pkt->size, 0x00, (struct sockaddr *) &from_ll, &fromlen);

    if ((ret != -1) && !(memcmp(&gw_send_ll.sll_addr, from_ll.sll_addr, ETH_ALEN)))
    {
        return ret;
    }
    else
    {
        errno = EAGAIN;
        return -1;
    }
}

static size_t netif_send(const struct packet* pkt)
{
    return sendto(fd[NET], pkt->buf, pkt->size, 0x00, (struct sockaddr *) &gw_send_ll, sizeof (gw_send_ll));
}

static size_t tunif_recv(const struct packet* pkt)
{
    return read(fd[TUN], pkt->buf, pkt->size);
}

static size_t tunif_send(const struct packet* pkt)
{
    return write(fd[TUN], pkt->buf, pkt->size);
}

static void recv_wrapper(int f, short event, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;

    if (pqueue[i == TUN ? NET : TUN].n == PQUEUE_LEN)
        event_del(&ev_recv[i]);

    if ((pbuf_recv[i] != NULL) || ((pbuf_recv[i] = new_packet(mtu)) != NULL))
    {
        const size_t ret = fd_recv[i](pbuf_recv[i]);
        if (ret != -1)
        {
            struct packet *pbuf_tmp = new_packet(ret);
            if (pbuf_tmp != NULL)
            {
                memcpy(pbuf_tmp->buf, pbuf_recv[i]->buf, ret);
                bufferedWrite(i, pbuf_tmp);
            }
            return;
        }
        else
        {
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
                event_loopbreak();
        }
    }
}

static void send_wrapper(int f, short event, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;

    if (pqueue[i == TUN ? NET : TUN].n < (PQUEUE_LEN))
        event_add(&ev_recv[i], NULL);

    if (pbuf_send[i] != NULL || ((pbuf_send[i] = bufferedRead(i)) != NULL))
    {
        const int ret = fd_send[i](pbuf_send[i]);

        if (ret == pbuf_send[i]->size)
        {
            free_packet(&pbuf_send[i]);

            if (pqueue[i].n)
                event_add(&ev_send[i], NULL);

            return;
        }
        else
        {
            if ((ret != -1) || ((errno != EAGAIN) && (errno != EWOULDBLOCK)))
                event_loopbreak();
            else
                event_add(&ev_send[i], NULL);
        }
    }
}

static void mitm_rs_error_error(enum mitm_t i)
{
    event_del(&ev_recv[i]);
    event_del(&ev_send[i]);

    close(fd[i]);
    fd[i] = -1;
    resetState(i);
    queue_clear(&pqueue[i]);

    switch (i)
    {
    case NETMITM:
        event_add(&ev_recv[NETMITMATTACH], NULL);
        break;
    case TUNMITM:
        event_add(&ev_recv[TUNMITMATTACH], NULL);
        break;
    default:
        printf("!? [%s:%u]: %u", __func__, __LINE__, i);
        raise(SIGTERM);

        break;
    }
}

static void mitmrecv_wrapper(int f, short event, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;

    int ret;

    if (pbuf_recv[i] == NULL)
    {
        uint16_t size;
        ret = recv(fd[i], &size, sizeof (size), MSG_WAITALL);
        if (ret == (sizeof (size)))
        {
            size = ntohs(size);
            if (size)
                pbuf_recv[i] = new_packet(size);

            return;
        }
    }
    else
    {
        ret = recv(fd[i], pbuf_recv[i]->buf, pbuf_recv[i]->size, MSG_WAITALL);
        if (ret == pbuf_recv[i]->size)
        {
            bufferedWrite(i, pbuf_recv[i]);
            pbuf_recv[i] = NULL;
            return;
        }
    }

    if ((ret != -1) || ((errno != EAGAIN) && (errno != EWOULDBLOCK)))
        mitm_rs_error_error(i);
}

static void mitmsend_wrapper(int f, short event, void *arg)
{
    const enum mitm_t i = *(enum mitm_t *) arg;

    int ret = 0;

    if ((pbuf_send[i] != NULL) || ((pbuf_send[i] = bufferedRead(i)) != NULL))
    {
        ret = send(fd[i], pbuf_send[i]->packed_buf, pbuf_send[i]->packed_size, 0);
        if (ret == pbuf_send[i]->packed_size)
        {
            free_packet(&pbuf_send[i]);

            if (pqueue[i].n)
                event_add(&ev_send[i], NULL);

            return;
        }

        if ((ret != -1) || ((errno != EAGAIN) && (errno != EWOULDBLOCK)))
            mitm_rs_error_error(i);

        else
            event_add(&ev_send[i], NULL);
    }
}

static void mitmattach_wrapper(int f, short event, void *arg)
{

    const enum mitm_t i = *(enum mitm_t *) arg;

    const int j = (i == NETMITMATTACH) ? NETMITM : TUNMITM;

    mitm_attach(i, j);

    event_set(&ev_recv[j], fd[j], EV_READ | EV_PERSIST, mitmrecv_wrapper, &handler_index[j]);
    event_set(&ev_send[j], fd[j], EV_WRITE, mitmsend_wrapper, &handler_index[j]);

    event_add(&ev_recv[j], NULL);
}

static uint8_t setupNET(void)
{
    int net = -1;

    struct ifreq tmpifr;
    uint32_t mac[6];
    int tmpfd;
    uint8_t i;

    if ((net = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
        runtime_exception("unable to open datalink layer for net interface");

    setfdflag(net, FD_CLOEXEC | O_NONBLOCK);

    memset(&tmpifr, 0x00, sizeof (tmpifr));
    strncpy(tmpifr.ifr_name, net_if, sizeof (tmpifr.ifr_name));
    if (ioctl(net, SIOCGIFINDEX, &tmpifr) == -1)
        runtime_exception("unable to execute ioctl(SIOCGIFINDEX) on interface %s", net_if);

    memset(&gw_send_ll, 0x00, sizeof (gw_send_ll));
    gw_send_ll.sll_family = PF_PACKET;
    gw_send_ll.sll_protocol = htons(ETH_P_IP);
    gw_send_ll.sll_ifindex = tmpifr.ifr_ifindex;
    gw_send_ll.sll_hatype = 0;
    gw_send_ll.sll_pkttype = PACKET_HOST;
    gw_send_ll.sll_halen = ETH_ALEN;

    sscanf(gw_mac, "%2x:%2x:%2x:%2x:%2x:%2x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    for (i = 0; i < ETH_ALEN; ++i)
        gw_send_ll.sll_addr[i] = mac[i];

    if (bind(net, (struct sockaddr *) &gw_send_ll, sizeof (gw_send_ll)) == -1)
        runtime_exception("unable to bind datalink layer on interface %s", net_if);

    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (ioctl(tmpfd, SIOCGIFMTU, &tmpifr) == -1)
        runtime_exception("unable to get MTU (SIOCGIFMTU) on interface: %s", net_if);
    mtu = tmpifr.ifr_mtu;

    close(tmpfd);

    return net;
}

static uint8_t setupTUN(void)
{
    int tun = -1;

    const char *tundev = "/dev/net/tun";

    struct ifreq tmpifr;
    int tmpfd;
    int i;

    if ((tun = open(tundev, O_RDWR)) == -1)
        runtime_exception("unable to open %s: check the kernel module", tundev);

    setfdflag(tun, FD_CLOEXEC | O_NONBLOCK);

    memset(&tmpifr, 0x00, sizeof (tmpifr));
    tmpifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    for (i = 0; i < 64; i++)
    {
        snprintf(tmpifr.ifr_name, sizeof (tmpifr.ifr_name), "%s%u", CONST_JANUS_IFNAME, i);
        if (!ioctl(tun, TUNSETIFF, &tmpifr))
            break;

        if (i == 63)
            runtime_exception("unable to set tun flags (TUNSETIFF)");
    }

    snprintf(tun_if, sizeof (tun_if), tmpifr.ifr_name);

    snprintf(tun_ip, sizeof (tun_ip), "%s%u", CONST_JANUS_FAKEGW_IP, i + 1);

    tmpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (ioctl(tmpfd, SIOCGIFFLAGS, &tmpifr) == -1)
        runtime_exception("unable to get tun flags (SIOCGIFFLAGS)");

    tmpifr.ifr_flags |= IFF_UP | IFF_RUNNING | IFF_POINTOPOINT;
    if (ioctl(tmpfd, SIOCSIFFLAGS, &tmpifr) == -1)
        runtime_exception("unable to get tun flags (SIOCSIFFLAGS)");

    tmpifr.ifr_mtu = mtu;
    if (ioctl(tmpfd, SIOCSIFMTU, &tmpifr) == -1)
        runtime_exception("unable to set tun mtu (SIOCSIFMTU)");

    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_addr.s_addr = inet_addr(net_ip);
    if (ioctl(tmpfd, SIOCSIFADDR, &tmpifr) == -1)
        runtime_exception("unable to set tun local addr to %s", net_ip);

    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *) &tmpifr.ifr_addr)->sin_addr.s_addr = inet_addr(tun_ip);
    if (ioctl(tmpfd, SIOCSIFDSTADDR, &tmpifr) == -1)
        runtime_exception("unable to set tun point-to-point dest addr to %s", tun_ip);

    close(tmpfd);

    return tun;
}

static int setupMitmAttach(uint16_t port)
{
    int fd = -1;
    int on = 1;
    struct sockaddr_in ssin;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        runtime_exception("unable to open socket");

    setfdflag(fd, FD_CLOEXEC);

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
    uint8_t i;

    execOSCmd(net_if, sizeof (net_if), "route -n | sed -n 's/^\\(%s\\).* \\([0-9.]\\{7,15\\}\\) .*\\(%s\\).*UG.* \\(.*\\)$/\\4/p'", conf.netip, conf.netmask);
    if (!strlen(net_if))
    {
        runtime_exception("unable to detect default gateway interface");
        return -1;
    }

    printf("detected default gateway interface: [%s]\n", net_if);

    execOSCmd(net_ip, sizeof (net_ip), "ifconfig %s | sed -n 's/.*inet addr:\\([0-9.]\\+\\) .*$/\\1/p'", net_if);
    if (!strlen(net_ip))
    {
        runtime_exception("unable to detect ", net_if, " ip address");
        return -1;
    }

    printf("detected local ip address on interface %s: [%s]\n", net_if, net_ip);

    execOSCmd(gw_ip, sizeof (gw_ip), "route -n | sed -n 's/^\\(%s\\).* \\([0-9.]\\{7,15\\}\\) .*\\(%s\\).*UG.* %s$/\\2/p'", conf.netip, conf.netmask, net_if);
    if (!strlen(gw_ip))
    {
        runtime_exception("unable to detect default gateway ip address");
        return -1;
    }

    printf("detected default gateway ip address: [%s]\n", gw_ip);

    execOSCmd(gw_mac, sizeof (gw_mac), "arp -ni %s %s | sed -n 's/^.*\\([a-f0-9:]\\{17,17\\}\\).*$/\\1/p'", net_if, gw_ip);
    if (!strlen(gw_mac))
    {
        runtime_exception("unable to detect default gateway mac address");
        return -1;
    }

    printf("detected default gateway mac address: [%s]\n", gw_mac);

    fd[NET] = setupNET();
    fd[TUN] = setupTUN();
    fd[NETMITM] = -1;
    fd[TUNMITM] = -1;
    fd[NETMITMATTACH] = setupMitmAttach(conf.listen_port_in);
    fd[TUNMITMATTACH] = setupMitmAttach(conf.listen_port_out);

    for (i = 0; i < 6; ++i)
    {
        if (i < 4)
        {
            pbuf_recv[i] = NULL;
            pbuf_send[i] = NULL;
            queue_init(&pqueue[i]);
        }

        handler_index[i] = (enum mitm_t)i;
    }

    fd_recv[NET] = netif_recv;
    fd_send[NET] = netif_send;

    fd_recv[TUN] = tunif_recv;
    fd_send[TUN] = tunif_send;

    execOSCmd(NULL, 0, "route del -net %s netmask %s gw %s dev %s", conf.netip, conf.netmask, gw_ip, net_if);
    execOSCmd(NULL, 0, "route add -net %s netmask %s gw %s dev %s", conf.netip, conf.netmask, tun_ip, tun_if);
    execOSCmd(NULL, 0, "iptables -A INPUT -m mac --mac-source %s -j DROP", gw_mac);

    return 0;
}

uint8_t JANUS_Shutdown(void)
{
    uint8_t i;
    for (i = 0; i < 6; ++i)
    {
        if (i < 4)
        {
            resetState(i);
            queue_clear(&pqueue[i]);
        }

        if (fd[i] != -1)
            close(fd[i]);
    }

    execOSCmd(NULL, 0, "route del -net %s netmask %s gw %s dev %s", conf.netip, conf.netmask, tun_ip, tun_if);
    execOSCmd(NULL, 0, "route add -net %s netmask %s gw %s dev %s", conf.netip, conf.netmask, gw_ip, net_if);
    execOSCmd(NULL, 0, "iptables -D INPUT -m mac --mac-source %s -j DROP", gw_mac);

    return 0;
}

void JANUS_EventLoop(void)
{
    event_init();

    event_set(&ev_send[NET], fd[NET], EV_WRITE, send_wrapper, &handler_index[NET]);
    event_set(&ev_send[TUN], fd[TUN], EV_WRITE, send_wrapper, &handler_index[TUN]);
    event_set(&ev_recv[NET], fd[NET], EV_READ | EV_PERSIST, recv_wrapper, &handler_index[NET]);
    event_set(&ev_recv[TUN], fd[TUN], EV_READ | EV_PERSIST, recv_wrapper, &handler_index[TUN]);
    event_set(&ev_recv[NETMITMATTACH], fd[NETMITMATTACH], EV_READ, mitmattach_wrapper, &handler_index[NETMITMATTACH]);
    event_set(&ev_recv[TUNMITMATTACH], fd[TUNMITMATTACH], EV_READ, mitmattach_wrapper, &handler_index[TUNMITMATTACH]);

    event_add(&ev_recv[NET], NULL);
    event_add(&ev_recv[TUN], NULL);
    event_add(&ev_recv[NETMITMATTACH], NULL);
    event_add(&ev_recv[TUNMITMATTACH], NULL);

    event_dispatch();
}
