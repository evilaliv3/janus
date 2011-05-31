/*
 *   Janus, a portable, unified and lightweight interface for mitm
 *   applications over the routing table.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "packet_queue.h"

struct packet* new_packet(uint32_t size)
{
    const uint32_t realsize = (sizeof (struct packet)) + (2 * (sizeof (uint16_t))) + size;

    struct packet * const ret = (struct packet *) malloc(realsize);

    if (ret != NULL)
    {
        ret->size = size;
        ret->buf = (uint8_t *) ret + (sizeof (struct packet)) + (sizeof (uint16_t));

        ret->packed_size = size + (sizeof (uint16_t));
        ret->packed_buf = (uint8_t *) ret + (sizeof (struct packet));
        *(uint16_t *) ret->packed_buf = htons(size);
    }

    return ret;
}

void free_packet(struct packet** pkt_p)
{
    if (*pkt_p != NULL)
    {
        free(*pkt_p);
        *pkt_p = NULL;
    }
}

void queue_init(struct packet_queue* q)
{
    q->n = 0;
    q->head = NULL;
    q->tail = NULL;
}

void queue_insert(struct packet_queue *q, struct packet *p)
{
    p->next = NULL;

    if (q->n == 0)
    {
        q->head = p;
        q->tail = p;
    }
    else
    {

        q->tail->next = p;
        q->tail = p;
    }

    q->n++;
}

struct packet* queue_extract(struct packet_queue *q)
{
    struct packet * const ret = q->head;

    if (ret != NULL)
    {
        q->head = q->head->next;
        q->n--;

        if (q->n == 0)
            q->tail = NULL;
    }

    return ret;
}

void queue_clear(struct packet_queue *q)
{
    struct packet *tmp;
    while ((tmp = queue_extract(q)) != NULL)
        free(tmp);
}
