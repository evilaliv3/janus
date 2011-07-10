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

#include "packet_queue.h"

struct packets* pbufs_malloc(uint16_t pkts_num, uint16_t pkts_size)
{
    uint16_t i;

    struct packets *pkts = malloc(sizeof (struct packets));
    if (pkts == NULL)
        return NULL;

    pkts->num = pkts_num;
    pkts->size = pkts_size;

    pkts->pdescriptor = malloc(pkts->num * sizeof(struct packet));
    if (pkts->pdescriptor == NULL)
    {
        free(pkts);
        return NULL;
    }

    pkts->pmemory = malloc(pkts->num * pkts->size);
    if (pkts->pmemory == NULL)
    {
        free(pkts->pdescriptor);
        free(pkts);
        return NULL;
    }

    for (i = 0; i < pkts->num; i++)
        pkts->pdescriptor[i].buf = &pkts->pmemory[i * pkts->size];

    pkts->free_packets = queue_malloc(pkts);
    if (pkts->free_packets == NULL)
    {
        free(pkts->pdescriptor);
        free(pkts->pmemory);
        free(pkts);
        return NULL;
    }

    pbufs_reset(pkts);

    return pkts;
}

void pbufs_reset(struct packets* pkts)
{
    uint32_t i;
    for (i = 0; i < pkts->num; i++)
        queue_push_back(pkts->free_packets, &pkts->pdescriptor[i]);
}

void pbufs_free(struct packets* pkts)
{
    queue_free(pkts->free_packets);
    free(pkts->pmemory);
    free(pkts->pdescriptor);
    free(pkts);
}

struct packet* pbuf_acquire(struct packets* pkts)
{
    struct packet* ret;
    if (queue_pop_front(pkts->free_packets, &ret) != -1)
        return ret;
    else
        return NULL;
}

void pbuf_release(struct packets* pkts, struct packet* pkt)
{
    queue_push_back(pkts->free_packets, pkt);
}

struct packet_queue* queue_malloc(struct packets* pkts)
{
    struct packet_queue* pq = malloc(sizeof (struct packet_queue));
    if (pq == NULL)
        return NULL;

    pq->records = malloc(pkts->num * sizeof (pkts->num));
    if (pq->records == NULL)
    {
        free(pq);
        return NULL;
    }

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

    while(queue_pop_front(pq, &pkt) != -1)
        queue_push_back(pq->pkts->free_packets, pkt);

}

int32_t queue_push_back(struct packet_queue *pq, struct packet *pkt)
{
    uint16_t pktnum = (pkt - pq->pkts->pdescriptor);

    if (pq->count == pq->pkts->num)
    {
        pbuf_release(pq->pkts, pkt);
        return -1;
    }

    pq->records[pq->head] = pktnum;

    pq->head = (pq->head + 1) % pq->pkts->num;

    pq->count++;

    return 0;
}

int32_t queue_pop_front(struct packet_queue *pq, struct packet **pkt)
{
    if (pq->count == 0)
        return -1;

    *pkt = &pq->pkts->pdescriptor[pq->records[pq->tail]];

    pq->tail = (pq->tail + 1) % pq->pkts->num;

    pq->count--;

    return 0;
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