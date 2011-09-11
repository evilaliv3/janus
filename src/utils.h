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
#ifndef JUTILS_H
#define JUTILS_H

#include <stdarg.h>

#define CONST_JANUS_BUFSIZE   512

/* symbol shared by janus.h able to be called from everywhere */
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

#define J_MEMORY_ERROR()      { runtime_exception("damn, unable to allocate memory [FILE: %s LINE: %u]", __FILE__, __LINE__); }
#define J_CLOSE(p)            if (*p != -1) { close(*p); *p = -1; }
#define J_PCAP_CLOSE(p)       if (*p != NULL) { pcap_close(*p); *p = NULL; }
#define J_BUFFEREVENT_FREE(p) if (*p != NULL) { bufferevent_free(*p); *p = NULL; }
#define J_PBUF_RELEASE(p)     if (*p != NULL) { pbuf_release(pbufs, *p); *p = NULL; }
#define J_MALLOC(ret,p)       if(((ret) = malloc(p)) == NULL) { J_MEMORY_ERROR() }
#define J_CALLOC(ret,p1,p2)   if(((ret) = calloc(p1, p2)) == NULL) { J_MEMORY_ERROR() }
#define J_STRDUP(ret,p)       if(((ret) = strdup(p)) == NULL) { J_MEMORY_ERROR() }

#endif /* JUTILS_H */
