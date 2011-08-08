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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "config_macros.h"

struct target_map 
{
    char *string;
    uint8_t index;
    void *command;
    void *output;
    void *test;
} os_cfg[] = {
    { "local interface name", STR_NET_IF, NULL, NULL, NULL },
    { "local interface IP", STR_NET_IP, NULL, NULL, NULL },
    { "local interface MAC", STR_NET_MAC, NULL, NULL, NULL },
    { "local interface MTU", STR_NET_MTU, NULL, NULL, NULL },
    { "tunnel interface name", STR_TUN_IF, NULL, NULL, NULL },
    { "tunnel interface IP", STR_TUN_IP, NULL, NULL, NULL },
    { "get local iface name", CMD_GET_NETIF, NULL, NULL, NULL },
    { "get local iface IP", CMD_GET_NETIP, NULL, NULL, NULL },
    { "get gateway IP", CMD_GET_GWIP, NULL, NULL, NULL },
    { "get gateway MAC", CMD_GET_GWMAC, NULL, NULL, NULL },
    { "set gateway route", CMD_ADD_REAL_DEFAULT_ROUTE, NULL, NULL, NULL },
    { "del gateway route", CMD_DEL_REAL_DEFAULT_ROUTE, NULL, NULL, NULL },
    { "set tunnel route", CMD_ADD_FAKE_DEFAULT_ROUTE, NULL, NULL, NULL },
    { "del tunnel route", CMD_DEL_FAKE_DEFAULT_ROUTE, NULL, NULL, NULL },
    { "add incoming filter", CMD_ADD_INCOMING_FILTER, NULL, NULL, NULL },
    { "del incoming filter", CMD_DEL_INCOMING_FILTER, NULL, NULL, NULL },
    { "add forward filter", CMD_ADD_FORWARD_FILTER, NULL, NULL, NULL },
    { "del incoming filter", CMD_DEL_FORWARD_FILTER, NULL, NULL, NULL },
    { "add tun masquerade", CMD_ADD_TUN_MASQUERADE, NULL, NULL, NULL },
    { "del tun masquerade", CMD_DEL_TUN_MASQUERADE, NULL, NULL, NULL },
    { "set tun", CMD_SET_TUN, NULL, NULL, NULL }
};

/* 
 * with janus package will became installed:
 * /etc/janus
 * /etc/janus/current-os -> /etc/janus/os-commands/Linux-whatever.janus
 *
 * Linux-whatever.janus is the configuration file containing the commands
 * executed to obtain the required effect on the running system.
 *
 * every new operating system must have a checked configuration file, with
 * the execution of janus-tester, an executable obtained compiling this file
 * with -DJANUS-TESTER in the command line.
 */
#define OSSELECTED  "/etc/janus/current-os"
#define LINESIZE    256

/* two, and only two "#" are expected in a command line */
int cmd_test_check(char *line)
{
    int cnt = 0, i = 0;

    for(i = 0 ; i < LINESIZE || line[i] == 0x00; i++)
        if(line[i] == '#') 
            cnt++;

    return (cnt == 2);
}

void *perm_extract(char *line)
{
    char swapL[LINESIZE];
    int i, j = 0;
    int good = 0;

    memset(&swapL, 0x00, LINESIZE);

    for(i = 0; i < strlen(line); i++)
    {
        if( good == 0 && line[i] == '#') {
            good = 1;
            continue;
        }

        if( good == 1 && line[i] == '#') {
            good = 0;
            break;
        }

        if( good )
            swapL[j++] = line[i];
    }

    return (void *)strdup(swapL);
}

int get_code_index(char *inpline, int *readed, uint8_t *mean)
{
    if( strlen(inpline) < 8 || !isdigit(inpline[0]) || !isdigit(inpline[1]) || 
        (inpline[2] != 'C' && inpline[2] != 'T') || inpline[3] != ' ' || inpline[4] != '#')
    {
        printf("invalid format in line: require \"DDC #\": digit digit code (T|C) space and #\n");
        return 0;
    }

    *readed = 0;
    /* the -48 is because 48 is the ASCII value of '0', this is not propery clean ;P */
    *readed += (((int)inpline[0] - 48) * 10);
    *readed += ((int)inpline[1] - 48);

    *mean = inpline[2];

    return 1;
}

/* janus configuration has a number and a "meaning"
 * 1C #command#
 * 1T #command showing the test of successful working of 1C#
 *    usage of format: the output of a command will be inserted with ~[number of command]
 *
 * example, 1 is "local interface name":
 * 1C #route -n | grep "0.0.0.0" | awk {'print $5'}#
 * 1T ##
 *
 * new example + remind: 4 is the number of "tunnel interface name"
 *             + remind: 10 is the number of "set tunnel gateway"
 * 10C #route add default gw ~4#
 * 10T #route -n#
 *                                               _______  ______________________________________
 * special characters in the configuration file: # and ~, THEY ARE NOT USABLE INSIDE THE COMMANS
 *                                               ^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 */
int janus_commands_file_setup(FILE *oscmds)
{
    int fndx = 0, ourndx = 0;
    uint8_t ourmean;

    while(!feof(oscmds))
    {
        char rdLine[LINESIZE];

        memset(&rdLine[0], 0x00, LINESIZE);
        fgets(rdLine, LINESIZE, oscmds);
        fndx++;

        if(strlen(rdLine) > (LINESIZE - 1) || strlen(rdLine) < 4 || rdLine[0] == '#')
            continue;

        if(rdLine[0] < '0' || rdLine[0] > '9') {
            printf("invalid non-number at the start of line %d\n", fndx);
            return 0;
        }

        if(!get_code_index(rdLine, &ourndx, &ourmean)) {
            printf("invalid number or code at the start of the line %d\n", fndx);
            return 0;
        }

        if(ourndx >= COMMANDS_NUM) {
            printf("command code too much higter (%d with a limit of %d), line %d\n",
                ourndx, COMMANDS_NUM, fndx);
            return 0;
        }

        if(!cmd_test_check(rdLine)) {
            printf("incorrect use of #..# at line %d [%s]\n", fndx, rdLine);
            return 0;
        }

        if(ourmean == 'C') /* command */ 
        {
            if((os_cfg[ourndx].command = perm_extract(rdLine)) == NULL) {
                printf("unable to parse correctly the \"command\" at line %d\n", fndx);
                return 0;
            }
        }

        if(ourmean == 'T') /* test */ 
        {
            if((os_cfg[ourndx].test = perm_extract(rdLine)) == NULL) {
                printf("unable to parse correctly the \"test\" at line %d\n", fndx);
                return 0;
            }
        }
    }

    return 1;
}

char *expand_command(char *original_rawcmd)
{
    /* as first: rawcmd is the stored buffer in the os_cfg global struct: must not be touched */
    char *tofree = strdup(original_rawcmd);
    char *rawcmd = tofree;

    static char retbuf[LINESIZE];
    char *p = strchr( rawcmd, (int)'~');
    int readVal = 0, j = 0;

    if(p == NULL) {
        free(tofree);
        return original_rawcmd;
    }

    printf("from [%s]\n", rawcmd);

    memset(&retbuf[0], ' ', LINESIZE);

    for( ; p != NULL ; p = strchr(rawcmd, '~') )
    {
        *p = 0x00;

/* printf(" %d ", j); */
        memcpy( &retbuf[j], rawcmd, strlen(rawcmd) );
        j += strlen(rawcmd) ;

/* printf(" %d (%d) [%s]", j, strlen(rawcmd), rawcmd); */
        readVal = (10 * ((int)*++p - 48) );
        readVal += (*++p - 48);
        rawcmd = ++p;

        /* remind: has to became _readVal_instead_of_0_ */
        memcpy( &retbuf[j], os_cfg[readVal].output, strlen(os_cfg[readVal].output) );
        j += strlen(os_cfg[readVal].output);

/* printf(" %d (%d) [%s] (di %d)\n", j, strlen(os_cfg[readVal].output), os_cfg[readVal].output, readVal); */
    }

    memcpy(&retbuf[j], rawcmd, strlen(rawcmd));
    j += strlen(rawcmd);
    retbuf[j] = 0x00;

    printf("to [%s]\n", retbuf);
    /* remind: rawcmd is the working copy to destroy, but the ptr *rawcmd is moved. "tofree" kept track */
    free(tofree);

    return &retbuf[0];
}

void clean_retbuf(char *retbuf, char *arrayofstrip)
{
    int i;
    for(i =0; i < strlen(arrayofstrip); i++)
    {
        char *underCheck = strchr(retbuf, arrayofstrip[i]);

        if(underCheck != NULL)
            *underCheck = 0x00;
    }
}

char *do_popen(char *command)
{
#define SIZEBULK    4096
    char buffer[SIZEBULK];
    FILE *outshell;

    memset(buffer, 0x00, SIZEBULK);

    printf("the command is [%s]\n", command);

    if((outshell = popen(command, "r")) == NULL) {
        printf("command [%s] no pipe open!\n", command);
        return NULL;
    }

    if(fgets(buffer, SIZEBULK, outshell) == NULL)
    {
        printf("command [%s] return no any answer!\n", command);
        return NULL;
    }
    pclose(outshell);

    clean_retbuf(buffer, "\r\n");
    return (char *)strdup(buffer);
}

char *do_os_command(int cmd_code)
{
    int i;

    /* get every possibile required string */
    for(i = 0; i < STRINGS_NUM; i++) 
    {
        if(os_cfg[i].output == NULL && (os_cfg[i].command != NULL)) 
        {
            printf("trying to expand %d: [%s]\n", i, (char *)os_cfg[i].command);
            os_cfg[i].output = do_popen(expand_command(os_cfg[i].command));
            if(os_cfg[i].output == NULL) 
            {
                printf("unable to fucking execute and read an answer from [%s]!!\n", (char *)os_cfg[i].command);
                return NULL;
            }
            printf("debug: output for %d is [%s]\n", i, (char *)os_cfg[i].output);
        }
    }

    printf("executing the requested command: %d [%s]\n", cmd_code, (char *)os_cfg[cmd_code].command);

    os_cfg[cmd_code].output = do_popen(expand_command(os_cfg[cmd_code].command));
    return os_cfg[cmd_code].output;
}

#ifdef JANUSTESTER
int main(int argc, char **argv)
{
    int i;
    FILE *input;

    if(argc != 2)
        return printf("%s [os selected command specification file]\ncheck janus(8) manpage!\n", argv[0]);

    if((input = fopen(argv[1], "r")) == NULL)
        return printf("unable to open %s\n", argv[1]);

    if(!janus_commands_file_setup(input))
        return;

    printf("testing of %s: extracting infos\n", argv[1]);

    for( i = 0; i < STRINGS_NUM; i++) {
        if(os_cfg[i].command != NULL)
            printf("%s: %s\n", os_cfg[i].string, do_os_command(i) );
        else
            printf("%s: not configured!\n");
    }

    printf("testing of %s: executing set/del commands\n", argv[1]);

    for( i = FIRST_CMD_NUMBER; i < LAST_CMD_NUMBER; i++) {
        if(os_cfg[i].command != NULL)
            printf("%s: %s\n", os_cfg[i].string, do_os_command(i) );
        else
            printf("%s: not configured!\n");
    }

    return 0;
}
#endif
