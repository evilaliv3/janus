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
#include <getopt.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <event.h>

#include "janus.h"

extern struct janus_config conf;

uint8_t main_alive;

static void janus_help(const char *pname)
{
#define JANUS_HELP_FORMAT \
    "Usage: Janus [OPTION]... :\n"\
    " --listen-ip\t\t<ip>\tset the listen ip address\n"\
    " --listen-port-in\t<port>\tset the listen port for incoming traffic\n"\
    " --listen-port-out\t<port>\tset the listen port for outgoing traffic\n"\
    " --pqueue-len\t\t<len>\tset tha internal packet queue length\n"\
    " --foreground\t\t\trun Janus in foreground\n"\
    " --version\t\t\tshow Janus version\n"\
    " --help\t\t\t\tshow this help\n\n"\
    "http://www.github.com/evilaliv3/janus\n"

    printf(JANUS_HELP_FORMAT);
}

static void janus_version(const char *pname)
{
    printf("Janus %s\n", CONST_JANUS_VERSION);
}

void handler_termination(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
        main_alive = 0;

    event_loopbreak();
}

static void sigtrapSetup(void(sigtrap_function) (int))
{
    sigset_t sig_nset;
    struct sigaction action;

    sigemptyset(&sig_nset);

    sigaddset(&sig_nset, SIGINT);
    sigaddset(&sig_nset, SIGABRT);
    sigaddset(&sig_nset, SIGPIPE);
    sigaddset(&sig_nset, SIGTERM);
    sigaddset(&sig_nset, SIGQUIT);

    memset(&action, 0, sizeof (action));
    action.sa_handler = sigtrap_function;
    action.sa_mask = sig_nset;

    sigaction(SIGINT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
}

uint8_t validate(const char *string, char *pattern)
{
    regex_t re;

    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) == 0)
    {
        int status = regexec(&re, string, (size_t) 0, NULL, 0);
        regfree(&re);

        return (status != 0) ? 0 : 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    uint8_t foreground = 0;

    int charopt;
    int port;
    int pqueue;

    struct option janus_options[] = {
        { "listen-ip", required_argument, NULL, 'l'},
        { "listen-port-in", required_argument, NULL, 'i'},
        { "listen-port-out", required_argument, NULL, 'o'},
        { "pqueue-len", required_argument, NULL, 'q'},
        { "foreground", no_argument, NULL, 'f'},
        { "version", no_argument, NULL, 'v'},
        { "help", no_argument, NULL, 'h'},
        { NULL, 0, NULL, 0}
    };

    snprintf(conf.listen_ip, sizeof (conf.listen_ip), "%s", CONST_JANUS_LISTEN_IP);
    conf.listen_port_in = CONST_JANUS_LISTEN_PORT_IN;
    conf.listen_port_out = CONST_JANUS_LISTEN_PORT_OUT;
    conf.pqueue_len = CONST_JANUS_PQUEUE_LEN;

    while ((charopt = getopt_long(argc, argv, "l:i:o:q:vh", janus_options, NULL)) != -1)
    {
        switch (charopt)
        {
        case 'l':
            if (validate(optarg, REGEXP_HOST))
                snprintf(conf.listen_ip, sizeof (conf.listen_ip), "%s", optarg);
            else
            {
                printf("invalid ip specified for listen-ip param\n");
                exit(1);
            }
            break;
        case 'i':
            port = atoi(optarg);
            if (port >= 0 && port <= 65535)
                conf.listen_port_in = (uint16_t) port;
            else
            {
                printf("invalid port specified for listen_port_in param\n");
                exit(1);
            }
            break;
        case 'o':
            port = atoi(optarg);
            if (port >= 0 && port <= 65535)
                conf.listen_port_out = (uint16_t) port;
            else
            {
                printf("invalid port specified for listen_port_out param\n");
                exit(1);
            }
            break;
        case 'q':
            pqueue = atoi(optarg);
            if (pqueue >= 0 && pqueue <= 65535)
                conf.pqueue_len = (uint16_t) pqueue;
            else
            {
                printf("invalid num specified for packet queue len param\n");
                exit(1);
            }
            break;
        case 'f':
            foreground = 1;
            break;
        case 'v':
            janus_version(argv[0]);
            return 0;
        case 'h':
            janus_help(argv[0]);
            return 0;
        default:
            janus_help(argv[0]);
            return -1;

            argc -= optind;
            argv += optind;
        }
    }

    if (getuid() || geteuid())
    {
        printf("root privileges required\n");
        exit(1);
    }

    if (!foreground)
    {
        int i, j, k;

        printf("Janus is now going in foreground, use SIGTERM to stop it.\n");

        if (fork())
            exit(0);

        setsid();

        for (i = getdtablesize(); i >= 0; --i)
            close(i);

        i = open("/dev/null", O_RDWR); /* stdin  */
        j = dup(i); /* stdout */
        k = dup(i); /* stderr */
        if (i != 0 || j != 1 || k != 2)
        {
            printf("error while closing stdin, stdout and stderr\n");
            exit(1);
        }
    }

    sigtrapSetup(handler_termination);

    main_alive = 1;

    JANUS_Bootstrap();

    while (main_alive)
    {
        JANUS_Init();

        JANUS_EventLoop();

        JANUS_Reset();
    }

    JANUS_Shutdown();

    exit(0);
}
