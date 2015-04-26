/*
 * hostapd - Layer2 packet snooping interface definition
 * Copyright (c) 2015, Michael Braun <michael-dev@fami-braun.de>
 *
 * Implementation based on l2_packet/l2_packet_pcap.c with modifications.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <pcap.h>

#include "common.h"
#include "eloop.h"
#include "l2_snoop.h"


struct l2_snoop_data {
	pcap_t *pcap;
	char ifname[100];
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len);
	void *rx_callback_ctx;
};


int l2_snoop_send(struct l2_snoop_data *l2, const u8 *buf, size_t len)
{
	int ret;

	if (l2 == NULL)
		return -1;

	ret = pcap_sendpacket(l2->pcap, buf, len);

	return ret;
}


static void l2_snoop_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct l2_snoop_data *l2 = eloop_ctx;
	pcap_t *pcap = sock_ctx;
	struct pcap_pkthdr hdr;
	const u_char *packet;
	struct l2_snoop_ethhdr *ethhdr;
	unsigned char *buf;
	size_t len;

	packet = pcap_next(pcap, &hdr);

	if (packet == NULL || hdr.caplen < sizeof(*ethhdr))
		return;

	ethhdr = (struct l2_snoop_ethhdr *) packet;
	buf = (unsigned char *) ethhdr;
	len = hdr.caplen;
	l2->rx_callback(l2->rx_callback_ctx, ethhdr->h_source, buf, len);
}


static int l2_snoop_init_libpcap(struct l2_snoop_data *l2,
				  unsigned short protocol)
{
	bpf_u_int32 pcap_maskp, pcap_netp;
	char pcap_filter[200], pcap_err[PCAP_ERRBUF_SIZE];
	struct bpf_program pcap_fp;

	pcap_lookupnet(l2->ifname, &pcap_netp, &pcap_maskp, pcap_err);
	l2->pcap = pcap_open_live(l2->ifname, 2500, 1, 10, pcap_err);
	if (l2->pcap == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", pcap_err);
		fprintf(stderr, "ifname='%s'\n", l2->ifname);
		return -1;
	}
	if (pcap_setnonblock(l2->pcap, 1, pcap_err) < 0)
		fprintf(stderr, "pcap_setnonblock: %s\n",
			pcap_geterr(l2->pcap));
	os_snprintf(pcap_filter, sizeof(pcap_filter),
		    "ether proto 0x%x", protocol);
	if (pcap_compile(l2->pcap, &pcap_fp, pcap_filter, 1, pcap_netp) < 0) {
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(l2->pcap));
		return -1;
	}

	if (pcap_setfilter(l2->pcap, &pcap_fp) < 0) {
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(l2->pcap));
		return -1;
	}

	pcap_freecode(&pcap_fp);

	eloop_register_read_sock(pcap_get_selectable_fd(l2->pcap),
				 l2_snoop_receive, l2, l2->pcap);

	return 0;
}


struct l2_snoop_data * l2_snoop_init(
	const char *ifname, unsigned short protocol,
	void (*rx_callback)(void *ctx, const u8 *src_addr,
			    const u8 *buf, size_t len),
	void *rx_callback_ctx)
{
	struct l2_snoop_data *l2;

	l2 = os_zalloc(sizeof(struct l2_snoop_data));
	if (l2 == NULL)
		return NULL;
	os_strlcpy(l2->ifname, ifname, sizeof(l2->ifname));
	l2->rx_callback = rx_callback;
	l2->rx_callback_ctx = rx_callback_ctx;

	if (l2_snoop_init_libpcap(l2, protocol)) {
		os_free(l2);
		return NULL;
	}

	return l2;
}


void l2_snoop_deinit(struct l2_snoop_data *l2)
{
	if (l2 == NULL)
		return;

	eloop_unregister_read_sock(pcap_get_selectable_fd(l2->pcap));
	if (l2->pcap)
		pcap_close(l2->pcap);
	os_free(l2);
}
