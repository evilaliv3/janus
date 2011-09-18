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

#ifndef J_PACKET_QUEUE_H
#define J_PACKET_QUEUE_H

#include <stdint.h>

struct packet;
struct packets;
struct packet_queue;

struct packet
{
    char *buf;
    uint16_t size;
};

struct packet_queue
{
    struct packets *pkts;
    uint16_t *records;
    uint16_t count;
    uint16_t head;
    uint16_t tail;
};

struct packets
{
    struct packet_queue *free_packets;
    struct packet *pdescriptor;
    char *pmemory;
    uint16_t num;
    uint16_t size;
};

struct packets* pbufs_malloc(uint16_t pkts_num, uint16_t pkts_size);
void pbufs_free(struct packets *pkts);

struct packet* pbuf_acquire(struct packets *pkts);
void pbuf_release(struct packets *pkts, struct packet *pkt);

struct packet_queue* queue_malloc(struct packets *pkts);
void queue_push_back(struct packet_queue *pq, struct packet *pkt);
struct packet* queue_pop_front(struct packet_queue *pq, struct packet **pkt);
void queue_reset(struct packet_queue *pq);
void queue_free(struct packet_queue *pq);

#endif /* J_PACKET_QUEUE_H */
