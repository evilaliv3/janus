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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "packet_queue.h"

struct packets* pbufs_malloc(uint16_t pkts_num, uint16_t pkts_size)
{
    struct packets *pkts;

    uint16_t i;

    J_MALLOC(pkts, sizeof (struct packets));

    pkts->num = pkts_num;
    pkts->size = pkts_size;
    pkts->free_packets = queue_malloc(pkts);

    J_MALLOC(pkts->pdescriptor, pkts->num * sizeof (struct packet));
    J_MALLOC(pkts->pmemory, pkts->num * pkts->size);

    for (i = 0; i < pkts->num; ++i)
    {
        pkts->pdescriptor[i].buf = &pkts->pmemory[i * pkts->size];
        queue_push_back(pkts->free_packets, &pkts->pdescriptor[i]);
    }

    return pkts;
}

void pbufs_free(struct packets *pkts)
{
    queue_free(pkts->free_packets);
    free(pkts->pmemory);
    free(pkts->pdescriptor);
    free(pkts);
}

struct packet* pbuf_acquire(struct packets* pkts)
{
    struct packet *ret;
    return queue_pop_front(pkts->free_packets, &ret);
}

void pbuf_release(struct packets *pkts, struct packet *pkt)
{
    queue_push_back(pkts->free_packets, pkt);
}

struct packet_queue* queue_malloc(struct packets *pkts)
{
    struct packet_queue *pq;

    J_MALLOC(pq, sizeof (struct packet_queue));
    J_MALLOC(pq->records, pkts->num * sizeof (pkts->num));

    pq->pkts = pkts;

    queue_reset(pq);

    return pq;
}

void queue_reset(struct packet_queue *pq)
{
    struct packet *pkt;

    pq->count = 0;
    pq->head = 0;
    pq->tail = 0;

    while (queue_pop_front(pq, &pkt) != NULL)
        queue_push_back(pq->pkts->free_packets, pkt);

}

void queue_push_back(struct packet_queue *pq, struct packet *pkt)
{
    uint16_t pktnum = (pkt - pq->pkts->pdescriptor);

    if (pq->count == pq->pkts->num)
    {
        pbuf_release(pq->pkts, pkt);
        return;
    }

    pq->records[pq->head] = pktnum;

    pq->head = (pq->head + 1) % pq->pkts->num;

    ++pq->count;
}

struct packet* queue_pop_front(struct packet_queue *pq, struct packet **pkt)
{
    if (pq->count == 0)
        return NULL;

    *pkt = &pq->pkts->pdescriptor[pq->records[pq->tail]];

    pq->tail = (pq->tail + 1) % pq->pkts->num;

    --pq->count;

    return *pkt;
}

void queue_free(struct packet_queue *pq)
{
    if (pq->records != NULL)
    {
        free(pq->records);
        pq->records = NULL;
    }

    free(pq);
}
