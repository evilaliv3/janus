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

#ifndef J_PACKET_QUEUE_H
#define J_PACKET_QUEUE_H

#include <stdint.h>

struct packet
{
    struct packet *next;

    uint16_t size;
    uint8_t *buf;

    uint16_t packed_size;
    uint8_t *packed_buf;
};

struct packet_queue
{
    size_t n;
    struct packet *head;
    struct packet *tail;
};

struct packet* new_packet(uint32_t size);
void free_packet(struct packet** pkt_p);
void queue_init(struct packet_queue *q);
void queue_insert(struct packet_queue *q, struct packet *p);
struct packet* queue_extract(struct packet_queue *q);
void queue_clear(struct packet_queue *q);

#endif /* J_PACKET_QUEUE_H */
