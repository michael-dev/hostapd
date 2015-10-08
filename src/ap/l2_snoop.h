/*
 * hostapd - Layer2 packet snooping interface definition
 * Copyright (c) 2015, Michael Braun <michael-dev@fami-braun.de>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file defines an interface for layer 2 (link layer) packet injecting
 * and snooping.
 */

#ifndef L2_SNOOP_H
#define L2_SNOOP_H

/**
 * struct l2_snoop_data - Internal l2_snoop data structure
 *
 * This structure is used by the l2_snoop implementation to store its private
 * data. Other files use a pointer to this data when calling the l2_snoop
 * functions, but the contents of this structure should not be used directly
 * outside l2_snoop implementation.
 */
struct l2_snoop_data;

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct l2_snoop_ethhdr {
	u8 h_dest[ETH_ALEN];
	u8 h_source[ETH_ALEN];
	be16 h_proto;
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

/**
 * l2_snoop_init - Initialize l2_snoop interface
 * @ifname: Interface name
 * @protocol: Ethernet protocol number in host byte order
 * @rx_callback: Callback function that will be called for each received packet
 * @rx_callback_ctx: Callback data (ctx) for calls to rx_callback()
 * Returns: Pointer to internal data or %NULL on failure
 *
 * rx_callback function will be called with src_addr pointing to the source
 * address (MAC address) of the the packet. Buf points to payload including
 * ethernet header.
 */
struct l2_snoop_data * l2_snoop_init(
	const char *ifname, unsigned short protocol,
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx);

/**
 * l2_snoop_deinit - Deinitialize l2_snoop interface
 * @l2: Pointer to internal l2_snoop data from l2_snoop_init()
 */
void l2_snoop_deinit(struct l2_snoop_data *l2);

/**
 * l2_snoop_send - Send a packet
 * @l2: Pointer to internal l2_snoop data from l2_snoop_init()
 * @buf: Packet contents to be sent; including layer 2 header.
 * @len: Length of the buffer (including l2 header)
 * Returns: >=0 on success, <0 on failure
 */
int l2_snoop_send(struct l2_snoop_data *l2, const u8 *buf, size_t len);

#endif /* L2_SNOOP_H */
