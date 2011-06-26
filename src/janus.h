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

#ifndef JANUS_H
#define JANUS_H

#define CONST_JANUS_VERSION         "0.1"
#define CONST_JANUS_IFNAME          "janus"
#define CONST_JANUS_NETIP           "0.0.0.0"
#define CONST_JANUS_NETMASK         "0.0.0.0"
#define CONST_JANUS_LISTEN_IP       "127.0.0.1"
#define CONST_JANUS_LISTEN_PORT_IN  30201
#define CONST_JANUS_LISTEN_PORT_OUT 10203
#define CONST_JANUS_BUFSIZE         4096
#define PQUEUE_LEN                  1024
#define REGEXP_IPV4                 "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})"
#define REGEXP_HOST                 "^"REGEXP_IPV4"$"

struct janus_config
{
    char netip [CONST_JANUS_BUFSIZE];
    char netmask [CONST_JANUS_BUFSIZE];
    char listen_ip [CONST_JANUS_BUFSIZE];
    uint16_t listen_port_in;
    uint16_t listen_port_out;
};

uint8_t JANUS_Bootstrap(void);
uint8_t JANUS_Shutdown(void);
void JANUS_EventLoop(void);

#endif /* JANUS_H */
