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
#include <stdlib.h>
#include <ctype.h>
#include "config_macros.h"
#include "janus.h"

static uint8_t os_present, mn_present;

#define ERROR_PARSER    0
#define GOOD_PARSING    1
#define NOT_MY_DATA     2

/* struct for tracking command & what's is printed out when the commands are exec'd */
struct janus_data_collect
{
    char Ji;
    const char *info;           /* information for the user */
    const char pc_info;         /* previously collected info */
    char *data;
} data_collect[] = 
{
    { '1', "get default gateway ip address", '0', NULL },
    { '2', "get the network interface linked to the gateway", '0', NULL },
    { '3', "get the ip address of ", '2', NULL },
    { '4', "get the MTU of ", '2', NULL },
    { '5', "get the MAC address of ", '2', NULL },
    { '6', "get the MAC address of ", '1', NULL },
    { '0', NULL, 0, NULL }
};

struct janus_mandatory_command
{
    char Ji;
    const char *info;
    char *acquired_string;
    char *command;
} mandatory_command[] =
{
    { '7', "add janus as gateway", NULL, NULL },
    { '8', "delete janus from begin gateway", NULL, NULL },
    { '9', "add filter dropping incoming traffic with orig GWs MAC", NULL, NULL },
    { 'A', "delete the filter dropping ", NULL, NULL },
    { 'B', "setup the tunnel", NULL, NULL },
    { 'C', "add addictional rule for forwarded traffic", NULL, NULL },
    { 'D', "delete the forward rule", NULL, NULL },
    { 'E', "delete the real default gateway", NULL, NULL },
    { 'G', "restore the real default gateway", NULL, NULL },
    { '0', NULL, NULL, NULL }
};
/*
 * remind special char:
 * ***********************************
 * T: tunnel name
 * Z: local endpoint ip address 
 * K: MTU value for the tun interface
 * ***********************************
 */
char *T = NULL, *Z = NULL, *K = NULL;

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
#define MAXLINESIZE 256

/* two, and only two "#" are expected in a command line */
static int line_sanity_check(char *line)
{
    int cnt = 0, i = 0;

    for(i = 0 ; i < MAXLINESIZE || line[i] == 0x00; i++)
        if(line[i] == '#') 
            cnt++;

    return (cnt == 2);
}

static char *poash_data_extract(char *line)
{
    char swapL[MAXLINESIZE];
    int i, j = 0;
    int good = 0;

    memset(&swapL, 0x00, MAXLINESIZE);

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

    return (char *)strdup(swapL);
}

static void clean_retbuf(char *retbuf, char *arrayofstrip)
{
    int i;
    for(i =0; i < strlen(arrayofstrip); i++)
    {
        char *underCheck = strchr(retbuf, arrayofstrip[i]);

        if(underCheck != NULL)
            *underCheck = 0x00;
    }
}

static char *do_popen(char *command)
{
#define SIZEBULK    4096
    char buffer[SIZEBULK];
    FILE *outshell;

    memset(buffer, 0x00, SIZEBULK);

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

static char *extract_simple(char *line)
{
    static char retb[MAXLINESIZE];
    int i;

    memset(retb, 0x00, MAXLINESIZE);
    for(i = 2; i < MAXLINESIZE && line[i] != 0x00; i++)
        retb[i - 2] = line[i];

    return &retb[0];
}

static int handle_OSName(char *line)
{
    if( line[0] == 'N' )
    {
        os_present++;
        printf(". configuration file written to work in: %s\n", extract_simple(line) );

        return os_present;
    }
    return 0;
}

int handle_Maintainer(char *line)
{
    if( line[0] == 'M' )
    {
        mn_present++;
        printf(". configuration file written by: %s, contact in case of errors\n", extract_simple(line) );

        return mn_present;
    }
    return 0;
}

static char *which_command(char *execname)
{
    char buffer[SIZEBULK], *ret;
    memset(buffer, 0x00, SIZEBULK);
    snprintf(buffer, SIZEBULK, "which %s", execname);

    /* do_popen use a static buffer */
    ret = do_popen(buffer);

    return ret;
}

/* return 0: ok the command, -1: not found, other: is not a command */
int handle_CheckCommand(char *line) 
{
    char *cmdret = NULL;

    if( line[0] == 'C' )
    {
        printf("checking existence of command [%s]: ", extract_simple(line) );

        /* we're using the static buffer of do_popen: don't relay on it */
        cmdret = which_command( extract_simple(line) );

        if(cmdret == NULL || strlen(cmdret) == 0)
        {
            printf(" executable not found!!\n");
            return ERROR_PARSER;
        }
        else
        {
            printf(" found at %s\n", cmdret);
            return GOOD_PARSING;
        }
    }
    return NOT_MY_DATA;
}

char *expand_command(char *original_rawcmd, struct janus_data_collect *jdc)
{
    /* as first: rawcmd is the stored buffer in the os_cfg global struct: must not be touched */
    char *tofree = strdup(original_rawcmd);
    char *rawcmd = tofree, *last_p = NULL, *p = NULL;

    static char retbuf[MAXLINESIZE];
    int j = 0;

    /* check if "~" exist at all */
    if ((p = strchr( rawcmd, (int)'~')) == NULL) {
        free(tofree);
        return original_rawcmd;
    }

    memset(&retbuf[0], ' ', MAXLINESIZE);

    last_p = &rawcmd[0];
    do 
    {
        /* delete the "~" and increment after */
        *p = 0x00; p++;

        memcpy( &retbuf[j], last_p, strlen(last_p) );
        j += strlen(last_p);

        /* remind: has to became _readVal_instead_of_0_ */
        memcpy( &retbuf[j], get_sysmap_str(*p), strlen(get_sysmap_str(*p)));

        j += strlen(get_sysmap_str(*p));

        /* delete the command code and increment after */
        *p = 0x00; p++; last_p = p;
        /* index to the next "~" if present */
        p = strchr(p, '~');
    } while (p != NULL );

    memcpy(&retbuf[j], last_p, strlen(last_p));
    j += strlen(last_p);
    retbuf[j] = 0x00;

    /* remind: rawcmd is the working copy to destroy, but the ptr *rawcmd is moved. "tofree" kept track */
    free(tofree);

    return &retbuf[0];
}

/* return 0: ok the command, -1: error, other: is not a command */
int collect_second_section(char *line, int lineNum)
{
    int i;

    if(line[0] != 'I')
        return NOT_MY_DATA;

    for (i = 0; data_collect[i].info != NULL; i++)
    {
        if(line[1] == data_collect[i].Ji)
        {
            char *swp = NULL;

            /* check if the command is not already memorized */
            if(data_collect[i].data != NULL)
            {
                printf("Invalid line %d: command index '%c' already executed (is %s)\n", lineNum, data_collect[i].Ji, data_collect[i].data);
                return ERROR_PARSER;
            }

            printf("%s", data_collect[i].info);

            if( data_collect[i].pc_info != '0' )
            {
                char *previous_info = get_sysmap_str(data_collect[i].pc_info);

                if( previous_info == NULL )
                {
                    printf("wrong order calling, request index of '%c' before having it\n", data_collect[i].pc_info);
                    return ERROR_PARSER;
                }

                /* else, the requested data for debug operations is correct */
                printf("%s", previous_info);
            }

            if((swp = expand_command(poash_data_extract(line), (struct janus_data_collect *)&data_collect)) == NULL)
            {
                printf(": error in expansion of the command [%s]\n", line);
                return ERROR_PARSER;
            }

            if((data_collect[i].data = do_popen(swp)) == NULL)
            {
                printf(": Error in command at line [%d]: don't return output.\n", lineNum);
                return ERROR_PARSER;
            }
            else
            {
                printf(": output acquired [%s]\n", data_collect[i].data);
                return GOOD_PARSING;
            }
        }
        /* skip next data_collet[].Ji */
    }

    printf("invalid command code after the 'I' in the line [%s]\n", line);
    return ERROR_PARSER;
}

int collect_third_section(char *line)
{
    int i;

    if(line[0] != 'S')
        return NOT_MY_DATA;

    for (i = 0; mandatory_command[i].info != NULL; i++)
    {
        if(line[1] == mandatory_command[i].Ji)
        {
            mandatory_command[i].acquired_string = poash_data_extract(line);

            mandatory_command[i].command = strdup(mandatory_command[i].acquired_string);

            if(mandatory_command[i].command == NULL)
            {
                printf("unable to expand command [%s]\n", mandatory_command[i].acquired_string);
                return ERROR_PARSER;
            }

            printf("%s: [%s]\n", mandatory_command[i].info, mandatory_command[i].command);

            /* in this phase we only collect these commands, because we don't want change 
             * the OS now */

            return GOOD_PARSING;
        }
    }

    printf("invalid command code after the 'S' in the line [%s]\n", line);
    return ERROR_PARSER;
}

/* 
 *                          *************************************
 *                          what's follow are the exported symbol
 *                          *************************************
 */

/* the main parsing routine: return 0 on error, return 1 on OK */
int janus_commands_file_setup(FILE *oscmds)
{
    int fndx = 0, i;

    if(oscmds == NULL)
    {
        printf("unable to open configuration file!\n");
        return 0;
    }

    while(!feof(oscmds))
    {
        int parserRet;
        char rdLine[MAXLINESIZE];
        memset(&rdLine[0], 0x00, MAXLINESIZE);

        fgets(rdLine, MAXLINESIZE, oscmds);
        fndx++;

        rdLine[strlen(rdLine) - 1] = 0x00;

        /* basic sanity checks */
        if(strlen(rdLine) > (MAXLINESIZE - 1) || strlen(rdLine) < 4 || rdLine[0] == ';')
            continue;

        /* make a surprise, when someone forgot a whitespace, don't make them sw broke! */
        if(rdLine[0] == ' ')
        {
            for(i = 0; i < (MAXLINESIZE -1); i++)
                if(rdLine[i] != ' ')
                    break;
                
            memmove(&rdLine[0], &rdLine[i], strlen(rdLine) - i);
        }

        /* handle the 'M' and 'N' keychars */
        if( handle_OSName(rdLine) || handle_Maintainer(rdLine) )
            continue;

        if (!os_present || !mn_present) {
            printf("invalid compilation detected at %d. supported OS name and maintainer: required\n", fndx);
            return 0;
        }

        /* 1st SECTION: the parsing of os-cmds/ require three stage analysis */
        parserRet = handle_CheckCommand(rdLine);
        switch(parserRet) {
            case NOT_MY_DATA:
                break;
            case GOOD_PARSING:
                continue;
            default: /* ERROR_PARSER */
                printf("invalid command checked at line: %d\n", fndx);
                return 0;
        }

        if(!line_sanity_check(rdLine)) 
        {
            printf("incorrect use of #..# at line %d\n", fndx);
            return 0;
        }

        /* 2nd SECTION: the data collection operation */
        parserRet = collect_second_section(rdLine, fndx);
        switch(parserRet) {
            case NOT_MY_DATA:
                break;
            case GOOD_PARSING:
                continue;
            default: /* ERROR_PARSER */
                printf("unable to collect information from command at line: %d\n", fndx);
                return 0;
        }

        /* 3rd SECTION: the system interfacing */
        parserRet = collect_third_section(rdLine);
        switch(parserRet) {
            case NOT_MY_DATA:
                break;
            case GOOD_PARSING:
                continue;
            default: /* ERROR_PARSER */
                printf("unable to acquire the mandatory command at line: %d\n", fndx);
                return 0;
        }

        printf("Invalid line %d: unable to handle [%s]\n", fndx, rdLine);
        return 0;
    }
    return 1;
}

void sysmap_command(char req)
{
    uint32_t i;

    for(i = 0; mandatory_command[i].Ji != '0'; i++)
    {
        if(mandatory_command[i].Ji == req) 
        {
            mandatory_command[i].command = strdup(
                                                expand_command(mandatory_command[i].acquired_string, 
                                                                (struct janus_data_collect *)&data_collect)
                                            );

            printf("+ %s [%s]\n", mandatory_command[i].info, mandatory_command[i].command);

            /* todo: could be useful use a different popen (different from do_popen) and check
             * if someshit is wiritten on strerr ? */
            system(mandatory_command[i].command);
            break;
        }
    }
}

char *get_sysmap_str(char req)
{
    uint32_t i;

    for(i = 0; data_collect[i].Ji != '0'; i++)
    {
        if(data_collect[i].Ji == req) 
        {
            return data_collect[i].data;
        }
    }

    /* handling of the three special character: K Z T */
    switch(req)
    {
        case 'K': /* MTU value */
            return "1200";
        case 'Z':
            return CONST_JANUS_FAKEGW_IP;
        case 'T':
            if(T == NULL)
                runtime_exception("has been requested element index by ~T before tunnel is opened!\n");
            else
                return T;
        default:
            runtime_exception("has been searched the command index with '%c': this element doesn't exist\n", req);
    }

    /* make gcc happy */
    return "janus win - and you never will see this line (except in github, gdb, etc...)";
}

void map_external_str(char req, char *data)
{
    if(data == NULL || strlen(data) <= 1)
        runtime_exception("something is going very bad in your code\n");

    switch(req)
    {
        case 'T':
            if(T != NULL)
                free(T);
            T = strdup(data);
            break;
        case 'Z':
            if(Z != NULL)
                free(Z);
            Z = strdup(data);
            break;
        case 'K':
            if(K != NULL)
                free(K);
            K = strdup(data);
            break;
        default:
            runtime_exception("has been searched the command index with '%c': this element could not be set\n", req);
    }
}

/* only the MTU 'K' could be mapped with an int */
void map_external_int(char req, uint32_t data)
{
    switch(req)
    {
        case 'K':
            if(K != NULL)
                free(K);
            K = calloc(10, 1);
            snprintf(K, 10, "%d", data);
            break;
        case 'Z':
        case 'T':
        default:
            runtime_exception("set with command index with '%c' using an INT: invalid data or index\n", req);
    }
}

void janus_conf_MTUfix(uint32_t diff)
{
    int32_t actvalue;

    if(K == NULL)
        runtime_exception("janus_conf_MTUfix call before MTU has been set\n");

    actvalue = atoi(K);

    if(actvalue < 0 || actvalue > 9000)
        runtime_exception("Invalid value present in MTU (string [%s] int [%d])\n", K, actvalue);

    actvalue -= diff;

    if(actvalue < 512 )
        runtime_exception("Invalid configuration, no MTU < 512 could be plausible in the Intertube\n");

    free(K);
    K = calloc(10, 1);
    snprintf(K, 10, "%d", actvalue);
}
