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

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

int tun_open(char *namebuf, size_t namebufsize)
{
    int tun = -1;

    const char *tundev = "/dev/net/tun";
    struct ifreq tmpifr;

    if ((tun = open(tundev, O_RDWR)) == -1)
        return -1;

    memset(&tmpifr, 0x00, sizeof (tmpifr));
    tmpifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(tun, TUNSETIFF, &tmpifr))
    {
        close(tun);
        return -1;
    }

    snprintf(namebuf, namebufsize, "%s", tmpifr.ifr_name);

    return tun;
}
