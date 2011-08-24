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

#ifndef JANUS_CONFIG_MACROS_H
#define JANUS_CONFIG_MACROS_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>


#define STR_NET_IF  0
#define STR_NET_IP  1
#define STR_NET_MAC 2
#define STR_NET_MTU 3
#define STR_TUN_IF  4
#define STR_TUN_IP  5
#define STR_TUN_MTU 6
#define STR_GW_MAC  7
#define STR_GW_IP   8
#define STRINGS_NUM 9

/*

collect2: ld returned 1 exit status
X-2:src X$ ./compila-macosx.sh 
ld: duplicate symbol _str_map in os_cmds.o and janus.o

*/

struct strings_map
{
    char *string;
    uint8_t index;
};

static struct strings_map str_map [] = {
    {"NET_IF", STR_NET_IF},
    {"NET_IP", STR_NET_IP},
    {"NET_MAC", STR_NET_MAC},
    {"NET_MTU", STR_NET_MTU},
    {"TUN_IF", STR_TUN_IF},
    {"TUN_IP", STR_TUN_IP},
    {"TUN_MAC", STR_TUN_MTU},
    {"GW_MAC", STR_GW_MAC},
    {"GW_IP", STR_GW_IP},
    {"STRINGS_NUM", 0},
    {NULL, 0}
};

#define CMD_GET_NETIF               0
#define CMD_GET_NETIP               1
#define CMD_GET_NETMAC              2
#define CMD_GET_NETMTU              3
#define CMD_GET_GWIP                4
#define CMD_GET_GWMAC               5
#define CMD_ADD_REAL_DEFAULT_ROUTE  6
#define CMD_DEL_REAL_DEFAULT_ROUTE  7
#define CMD_ADD_FAKE_DEFAULT_ROUTE  8
#define CMD_DEL_FAKE_DEFAULT_ROUTE  9
#define CMD_ADD_INCOMING_FILTER    10
#define CMD_DEL_INCOMING_FILTER    11
#define CMD_ADD_FORWARD_FILTER     12
#define CMD_DEL_FORWARD_FILTER     13
#define CMD_ADD_TUN_MASQUERADE     14
#define CMD_DEL_TUN_MASQUERADE     15
#define CMD_SETUP_TUN              16
#define COMMANDS_NUM               17

struct cmds_map
{
    char *cmd;
    uint8_t index;
};

static struct cmds_map cmd_map [] = {
    {"CMD_GET_NETIF", CMD_GET_NETIF},
    {"CMD_GET_NETIP", CMD_GET_NETIP},
    {"CMD_GET_NETMAC", CMD_GET_NETMAC},
    {"CMD_GET_NETMTU", CMD_GET_NETMTU},
    {"CMD_GET_GWIP", CMD_GET_GWIP},
    {"CMD_GET_GWMAC", CMD_GET_GWMAC},
    {"CMD_ADD_REAL_DEFAULT_ROUTE", CMD_ADD_REAL_DEFAULT_ROUTE},
    {"CMD_DEL_REAL_DEFAULT_ROUTE", CMD_DEL_REAL_DEFAULT_ROUTE},
    {"CMD_ADD_FAKE_DEFAULT_ROUTE", CMD_ADD_FAKE_DEFAULT_ROUTE},
    {"CMD_DEL_FAKE_DEFAULT_ROUTE", CMD_DEL_FAKE_DEFAULT_ROUTE},
    {"CMD_ADD_INCOMING_FILTER", CMD_ADD_INCOMING_FILTER},
    {"CMD_DEL_INCOMING_FILTER", CMD_DEL_INCOMING_FILTER},
    {"CMD_ADD_FORWARD_FILTER", CMD_ADD_FORWARD_FILTER},
    {"CMD_DEL_FORWARD_FILTER", CMD_DEL_FORWARD_FILTER},
    {"CMD_ADD_TUN_MASQUERADE", CMD_ADD_TUN_MASQUERADE},
    {"CMD_DEL_TUN_MASQUERADE", CMD_DEL_TUN_MASQUERADE},
    {"CMD_SETUP_TUN", CMD_SETUP_TUN},
    {"COMMANDS_NUM", 0},
    {NULL, 0}
};

#endif /* JANUS_CONFIG_MACROS_H */
