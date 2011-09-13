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

#include "janus.h"
#include "utils.h"

static uint8_t os_present, mn_present;

#define ERROR_PARSER    0
#define GOOD_PARSING    1
#define NOT_MY_DATA     2

/* struct for tracking command & what's is printed out when the commands are exec'd */
struct janus_data_collect
{
    char Ji;
    const char * const info;    /* information for the user */
    const char pc_info;         /* previously collected info */
    char *data;
} data_collect[] = 
{
    { '1', "default gateway ip address", '0', NULL },
    { '2', "network interface linked to the gateway", '0', NULL },
    { '3', "ip address of ", '2', NULL },
    { '4', "MTU of ", '2', NULL },
    { '5', "MAC address of ", '2', NULL },
    { '6', "MAC address of ", '1', NULL },
    { '0', NULL, 0, NULL }
};

struct janus_mandatory_command
{
    char Ji;
    const char * const info;
    char *acquired_string;
    char *command;
} mandatory_command[] =
{
    { '7', "add fake arp entry", NULL, NULL },
    { '8', "del fake arp entry", NULL, NULL },
    { '9', "add iptables filter dropping incoming traffic with real default gw mac", NULL, NULL },
    { 'A', "del iptables filter dropping incoming traffic with real default gw mac", NULL, NULL },
    { 'B', "add addictional rule for forwarded traffic", NULL, NULL },
    { 'C', "del addictional rule for forwarded traffic", NULL, NULL },
    { '0', NULL, NULL, NULL }
};

/*
 * remind special char:
 * ***********************************
 * Z: local endpoint ip address 
 * ***********************************
 */
char *Z = NULL;

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
static uint32_t line_sanity_check(char *line)
{
    uint32_t i = 0, cnt = 0;

    for(i = 0; i < MAXLINESIZE && line[i] != 0x00; ++i)
        if(line[i] == '#') 
            ++cnt;

    return (cnt == 2);
}

static char* poash_data_extract(char *line)
{
    char * ret;

    char swapL[MAXLINESIZE] = {0};

    uint32_t i, j, good;

    for(i = j = good = 0; i < MAXLINESIZE && line[i] != 0x00; ++i)
    {
        if( line[i] == '#') {
            if(good == 0) {
                good = 1;
                continue;
            } else {
                break;
            }
        }

        if( good )
            swapL[j++] = line[i];
    }

    J_STRDUP(ret, swapL);

    return ret;
}

static void clean_retbuf(char *retbuf, char *arrayofstrip)
{
    uint32_t i;

    for(i = 0; i < strlen(arrayofstrip); ++i)
    {
        char *underCheck = strchr(retbuf, arrayofstrip[i]);

        if(underCheck != NULL)
            *underCheck = 0x00;
    }
}

static char* do_popen(char *command)
{
#define SIZEBULK    4096

    char *ret;

    char buffer[SIZEBULK] = {0};
    FILE *outshell;

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

    J_STRDUP(ret, buffer);

    return ret;
}

static char* extract_simple(char *line)
{
    char *ret;

    char buffer[MAXLINESIZE] = {0};

    uint32_t i;

    for(i = 2; i < MAXLINESIZE && line[i] != 0x00; ++i)
        buffer[i - 2] = line[i];

    J_STRDUP(ret, buffer);

    return ret;
}

static uint32_t handle_OSName(char *line)
{
    if( line[0] == 'N' )
    {
        char *tmp = extract_simple(line);

        if(os_present)
            runtime_exception("repeated N param inside configuration file");

        os_present = 1;
        printf(". configuration file written to work in: %s\n", tmp );
        
        free(tmp);

        return os_present;
    }

    return 0;
}

static uint32_t handle_Maintainer(char *line)
{
    if( line[0] == 'M' )
    {
        char *tmp = extract_simple(line);

        if(mn_present)
            runtime_exception("repeated M param inside configuration file");

        mn_present = 1;

        printf(". configuration file written by: %s, contact in case of errors\n", tmp );

        free(tmp);

        return mn_present;
    }

    return 0;
}

static char* which_command(char *execname)
{
    char buffer[SIZEBULK] = {0};

    snprintf(buffer, SIZEBULK, "which %s", execname);

    return do_popen(buffer);
}

/* return 0: ok the command, -1: not found, other: is not a command */
static uint32_t handle_CheckCommand(char *line) 
{
    uint32_t ret = NOT_MY_DATA;

    char *cmdret = NULL;

    if( line[0] == 'C' )
    {
        char *tmp = extract_simple(line);

        printf("[check] existence of command [%s]: ", tmp );

        /* we're using the static buffer of do_popen: don't relay on it */
        cmdret = which_command(tmp);

        free(tmp);

        if(cmdret == NULL || strlen(cmdret) == 0)
        {
            printf("executable not found\n");
            ret =  ERROR_PARSER;
        }
        else
        {
            printf("found at %s\n", cmdret);
            ret = GOOD_PARSING;
        }

        if(cmdret != NULL)
            free(cmdret);
    }

    return ret;
}

static char *expand_command(char *original_rawcmd)
{
    char *ret, *tofree, *last_p, *p;

    char buffer[MAXLINESIZE] = {' '};
    uint32_t j = 0;

    J_STRDUP(tofree, original_rawcmd);

    /* check if "~" exist at all */
    if ((p = strchr( tofree, (int)'~')) == NULL) {
        free(tofree);
        J_STRDUP(ret, original_rawcmd);
        return ret;
    }

    last_p = tofree;

    do 
    {
        /* delete the "~" and increment after */
        *p = 0x00; ++p;

        memcpy( &buffer[j], last_p, strlen(last_p) );
        j += strlen(last_p);

        /* remind: has to became _readVal_instead_of_0_ */
        memcpy( &buffer[j], get_sysmap_str(*p), strlen(get_sysmap_str(*p)));

        j += strlen(get_sysmap_str(*p));

        /* delete the command code and increment after */
        *p = 0x00; ++p; last_p = p;
        /* index to the next "~" if present */
        p = strchr(p, '~');
    } while (p != NULL );

    memcpy(&buffer[j], last_p, strlen(last_p));
    j += strlen(last_p);
    buffer[j] = 0x00;

    /* remind: rawcmd is the working copy to destroy, but the ptr *rawcmd is moved. "tofree" kept track */
    free(tofree);

    J_STRDUP(ret, buffer);

    return ret;
}

/* return 0: ok the command, -1: error, other: is not a command */
uint32_t collect_second_section(char *line, int lineNum)
{
    uint32_t i;

    if(line[0] != 'I')
        return NOT_MY_DATA;

    for (i = 0; data_collect[i].Ji != '0'; ++i)
    {
        if(line[1] == data_collect[i].Ji)
        {
            char *tmp = NULL, *swp = NULL;

            /* check if the command is not already memorized */
            if(data_collect[i].data != NULL)
            {
                printf("invalid line %d: command index '%c' already executed (is %s)\n", lineNum, data_collect[i].Ji, data_collect[i].data);
                return ERROR_PARSER;
            }

            printf("[get_info] %s", data_collect[i].info);

            if( data_collect[i].pc_info != '0' )
            {
                char *previous_info = get_sysmap_str(data_collect[i].pc_info);

                if( previous_info == NULL )
                {
                    printf("wrong order calling, request index of '%c' before having it\n", data_collect[i].pc_info);
                    return ERROR_PARSER;
                }

                /* else, the requested data for debug operations is correct */
                printf(" %s", previous_info);
            }

            tmp = poash_data_extract(line);
            swp = expand_command(tmp);

            free(tmp);

            if(swp == NULL)
            {
                printf(": error in expansion of the command [%s]\n", line);
                return ERROR_PARSER;
            }

            data_collect[i].data = do_popen(swp);

            free(swp);

            if(data_collect[i].data == NULL)
            {
                printf(": error in command at line [%d]: no output returned.\n", lineNum);
                return ERROR_PARSER;
            }
            else
            {
                printf(": [%s]\n", data_collect[i].data);
                return GOOD_PARSING;
            }
        }
        /* skip next data_collet[].Ji */
    }

    printf("invalid command code after the 'I' in the line [%s]\n", line);
    return ERROR_PARSER;
}

uint32_t collect_third_section(char *line)
{
    uint32_t i;

    if(line[0] != 'S')
        return NOT_MY_DATA;

    for (i = 0; mandatory_command[i].Ji != '0'; ++i)
    {
        if(line[1] == mandatory_command[i].Ji)
        {
            mandatory_command[i].acquired_string = poash_data_extract(line);

            printf("[build_cmd] %s: [%s]\n", mandatory_command[i].info, mandatory_command[i].acquired_string);

            /* in this phase we only collect these commands, because we don't want change 
             * the OS now */

            return GOOD_PARSING;
        }
    }

    printf("invalid command code after the 'S' in the line [%s]\n", line);
    return ERROR_PARSER;
}

/* 
 *                         **************************************
 *                         what's follow are the exported symbols
 *                         **************************************
 */

/* the main parsing routine: return 0 on error, return 1 on OK */
void janus_commands_file_setup(FILE *oscmds)
{
    uint32_t fndx = 0, i;

    if(oscmds == NULL)
        runtime_exception("unable to open configuration file\n");

    while(!feof(oscmds))
    {
        uint32_t parserRet;
        char rdLine[MAXLINESIZE] = {0};

        fgets(rdLine, MAXLINESIZE, oscmds);
        ++fndx;

        rdLine[strlen(rdLine) - 1] = 0x00;

        /* basic sanity checks */
        if(strlen(rdLine) > (MAXLINESIZE - 1) || strlen(rdLine) < 4 || rdLine[0] == ';')
            continue;

        /* make a surprise, when someone forgot a whitespace, don't make them sw broke! */
        if(rdLine[0] == ' ')
        {
            for(i = 0; i < (MAXLINESIZE -1); ++i)
                if(rdLine[i] != ' ')
                    break;
                
            memmove(&rdLine[0], &rdLine[i], strlen(rdLine) - i);
        }

        /* handle the 'M' and 'N' keychars */
        if( handle_OSName(rdLine) || handle_Maintainer(rdLine) )
            continue;

        if (!os_present || !mn_present)
            runtime_exception("invalid compilation detected at %d. supported OS name and maintainer: required\n", fndx);

        /* 1st SECTION: the parsing of os-cmds/ require three stage analysis */
        parserRet = handle_CheckCommand(rdLine);
        switch(parserRet) {
            case NOT_MY_DATA:
                break;
            case GOOD_PARSING:
                continue;
            default: /* ERROR_PARSER */
                runtime_exception("invalid command checked at line: %d\n", fndx);
        }

        if(!line_sanity_check(rdLine)) 
            runtime_exception("incorrect use of #..# at line %d\n", fndx);

        /* 2nd SECTION: the data collection operation */
        parserRet = collect_second_section(rdLine, fndx);
        switch(parserRet) {
            case NOT_MY_DATA:
                break;
            case GOOD_PARSING:
                continue;
            default: /* ERROR_PARSER */
                runtime_exception("unable to collect information from command at line: %d\n", fndx);
        }

        /* 3rd SECTION: the system interfacing */
        parserRet = collect_third_section(rdLine);
        switch(parserRet) {
            case NOT_MY_DATA:
                break;
            case GOOD_PARSING:
                continue;
            default: /* ERROR_PARSER */
                runtime_exception("unable to acquire the mandatory command at line: %d\n", fndx);
        }

        runtime_exception("invalid line %d: unable to handle [%s]\n", fndx, rdLine);
    }
}

void sysmap_command(char req)
{
    uint32_t i;

    for(i = 0; mandatory_command[i].Ji != '0'; ++i)
    {
        if(mandatory_command[i].Ji == req) 
        {
            mandatory_command[i].command = expand_command(mandatory_command[i].acquired_string); 

            printf("[exec_cmd] %s [%s]\n", mandatory_command[i].info, mandatory_command[i].command);

            /* todo: could be useful use a different popen (different from do_popen) and check
             * if someshit is written on strerr ? */
            system(mandatory_command[i].command);
            break;
        }
    }
}

char *get_sysmap_str(char req)
{
    uint32_t i;

    for(i = 0; data_collect[i].Ji != '0'; ++i)
    {
        if(data_collect[i].Ji == req) 
            return data_collect[i].data;
    }

    /* handling of the three special character: Z */
    switch(req)
    {
        case 'Z':
            return CONST_JANUS_FAKEGW_IP;
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
        case 'Z':
            if(Z != NULL)
                free(Z);
            J_STRDUP(Z, data);
            break;
        default:
            runtime_exception("has been searched the command index with '%c': this element could not be set\n", req);
    }
}

void free_cmd_structures(void)
{
    uint32_t i;

    for (i = 0; data_collect[i].Ji != '0'; ++i)
    {
        if( data_collect[i].data != NULL)
            free(data_collect[i].data);
    }

    for (i = 0; mandatory_command[i].Ji != '0'; ++i)
    {
        if(mandatory_command[i].acquired_string != NULL)
            free(mandatory_command[i].acquired_string);

        if(mandatory_command[i].command != NULL)
            free(mandatory_command[i].command);
    }
}
