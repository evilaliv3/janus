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

/* instead include ethernet.h */
#ifndef ETH_HLEN
#define ETH_HLEN              14
#endif

#ifndef ETH_ALEN
#define ETH_ALEN              6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP              0x0800
#endif
/* --- */

#define CONST_JANUS_VERSION         "0.3"
#define CONST_JANUS_IFNAME          "janus"
#define CONST_JANUS_WEBSITE         "http://github.com/evilaliv3/janus"
#define CONST_JANUS_CONF_FILE       "/etc/janus/current-os"
#define CONST_JANUS_LISTEN_IP       "127.0.0.1"
#define CONST_JANUS_LISTEN_PORT_IN  30201
#define CONST_JANUS_LISTEN_PORT_OUT 10203
#define CONST_JANUS_BUFSIZE         512
#define CONST_JANUS_PQUEUE_LEN      32
#define REGEXP_IPV4                 "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})"
#define REGEXP_HOST                 "^"REGEXP_IPV4"$"

#define JANUS_BANNER                " Janus-"CONST_JANUS_VERSION" "CONST_JANUS_WEBSITE" "
#define CONST_JANUS_BANNER_LENGTH   sizeof(JANUS_BANNER)

struct ethernet_header
{
    uint8_t dst_ethernet[ETH_ALEN];
    uint8_t src_ethernet[ETH_ALEN];
    uint16_t link_type;
} __attribute__((__packed__));

struct janus_config
{
    char banner[CONST_JANUS_BANNER_LENGTH];
    char file[CONST_JANUS_BUFSIZE];
    char listen_ip[CONST_JANUS_BUFSIZE];
    uint16_t listen_port_in;
    uint16_t listen_port_out;
    uint16_t pqueue_len;
};

void JANUS_Bootstrap(void);
void JANUS_Init(void);
void JANUS_Reset(void);
void JANUS_Shutdown(void);
void JANUS_EventLoop(void);

/* these are the exported symbol from os_cmds.c */
void janus_commands_file_setup(char *);
void sysmap_command(char);
char *get_sysmap_str(char);
uint32_t get_sysmap_int(char);
void map_external_int(char, uint32_t);
void free_cmd_structures(void);

#endif /* JANUS_H */
