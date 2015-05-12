/*
 * Wired-ng Ethernet driver interface
 * This is only for linux and only for hostapd.
 *
 * Copyright (c) 2014, Michael Braun <michael-dev@fami-braun.de>
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004, Gunter Burchardt <tira@isx.de>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifdef HOSTAPD
#ifdef __linux__

#include "utils/includes.h"
#include "utils/common.h"
 
#include "includes.h"
#include <sys/ioctl.h>
#include <netpacket/packet.h>

#include "common.h"
#include "eloop.h"
#include "driver.h"
#include "linux_ioctl.h"
#include "ap/macvlan.h"

#include <net/if.h>
#include "drivers/netlink.h"
#include "drivers/priv_netlink.h"


struct ieee8023_hdr {
	u8 dest[6];
	u8 src[6];
	u16 ethertype;
} STRUCT_PACKED;

static const u8 pae_group_addr[ETH_ALEN] =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };


struct wpa_driver_wiredng_sta {
	u8 addr[ETH_ALEN];
	int ifidx;
};

struct wpa_driver_wiredng_data {
	char ifname[IFNAMSIZ + 1];
	int ifidx;
	void *ctx;

	int sock; /* raw packet socket for driver access */
	int use_pae_group_addr;

	int pf_sock;
	int membership, multi, iff_allmulti, iff_up;

	int numVlanInterfaces;
	int* vlanInterfaceIdx;

	struct netlink_data * nl;

	int numSTA;
	struct wpa_driver_wiredng_sta *sta;
};


static int wired_multicast_membership(int sock, int ifindex,
				      const u8 *addr, int add)
{
	struct packet_mreq mreq;

	if (sock < 0)
		return -1;

	os_memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	os_memcpy(mreq.mr_address, addr, ETH_ALEN);

	if (setsockopt(sock, SOL_PACKET,
		       add ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		       &mreq, sizeof(mreq)) < 0) {
		perror("setsockopt");
		return -1;
	}
	return 0;
}


static void handle_data(void *ctx, unsigned char *buf, size_t len)
{
	struct ieee8023_hdr *hdr;
	u8 *pos, *sa;
	size_t left;
	union wpa_event_data event;

	/* must contain at least ieee8023_hdr 6 byte source, 6 byte dest,
	 * 2 byte ethertype */
	if (len < 14) {
		wpa_printf(MSG_MSGDUMP, "handle_data: too short (%lu)",
			   (unsigned long) len);
		return;
	}

	hdr = (struct ieee8023_hdr *) buf;

	switch (ntohs(hdr->ethertype)) {
		case ETH_P_PAE:
			wpa_printf(MSG_MSGDUMP, "Received EAPOL packet");
			sa = hdr->src;
			os_memset(&event, 0, sizeof(event));
			event.new_sta.addr = sa;
			wpa_supplicant_event(ctx, EVENT_NEW_STA, &event);

			pos = (u8 *) (hdr + 1);
			left = len - sizeof(*hdr);
			drv_event_eapol_rx(ctx, sa, pos, left);
		break;

	default:
		wpa_printf(MSG_DEBUG, "Unknown ethertype 0x%04x in data frame",
			   ntohs(hdr->ethertype));
		break;
	}
}


static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return;
	}

	handle_data(eloop_ctx, buf, len);
}


static int driver_wiredng_flush(void *priv)
{
	struct wpa_driver_wiredng_data *drv = priv;
	int i;

	/* cable is not connected, flush all macs */
	for (i = 0; i < drv->numSTA; i++)
		drv_event_disassoc(drv->ctx, drv->sta[i].addr);
	drv->numSTA = 0;

	for (i = 0; i < drv->numVlanInterfaces; i++) {
		macvlan_interface_change_mac(drv->vlanInterfaceIdx[i], 0, NULL);
	}

	return 0;
}


static void wired_event_receive_newlink(void *ctx,struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	struct wpa_driver_wiredng_data *drv = ctx;

	if (!ifi || ifi->ifi_index != drv->ifidx)
		return;

	int flags = ifi->ifi_flags;

	if (flags & IFF_RUNNING) {
		wpa_printf(MSG_DEBUG, "wiredng: Interface %s is up", drv->ifname);
		return;
	}
	
	wpa_printf(MSG_DEBUG, "wiredng: Interface %s is down", drv->ifname);
	driver_wiredng_flush(drv);
}


static int wired_init_sockets(struct wpa_driver_wiredng_data *drv, u8 *own_addr)
{
	struct sockaddr_ll addr;
	struct netlink_config *cfg = 0;

	drv->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if (drv->sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	if (eloop_register_read_sock(drv->sock, handle_read, drv->ctx, NULL)) {
		printf("Could not register read socket\n");
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = drv->ifidx;
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(drv->sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

	/* set link up */
	linux_set_iface_flags(drv->sock, drv->ifname, 1);

	/* filter multicast address */
	if (wired_multicast_membership(drv->sock, drv->ifidx,
				       pae_group_addr, 1) < 0) {
		wpa_printf(MSG_ERROR, "wired: Failed to add multicast group "
			   "membership");
		return -1;
	}

	/* check device type and get mac */
	if (linux_get_ifhwaddr(drv->sock, drv->ifname, own_addr) < 0)
		return -1;

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;

	cfg->ctx = drv;
	cfg->newlink_cb = wired_event_receive_newlink;
	drv->nl = netlink_init(cfg);
        if (drv->nl == NULL)
	{
		wpa_printf(MSG_ERROR, "wired: %s: netlink_init failed: %s",
			   __func__, strerror(errno));
		return -1;
	}

	return 0;
}


static int wired_send_eapol(void *priv, const u8 *addr,
			    const u8 *data, size_t data_len, int encrypt,
			    const u8 *own_addr, u32 flags)
{
	struct wpa_driver_wiredng_data *drv = priv;
	struct ieee8023_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + data_len;
	hdr = os_zalloc(len);
	if (hdr == NULL) {
		printf("malloc() failed for wired_send_eapol(len=%lu)\n",
		       (unsigned long) len);
		return -1;
	}

	os_memcpy(hdr->dest, drv->use_pae_group_addr ? pae_group_addr : addr,
		  ETH_ALEN);
	os_memcpy(hdr->src, own_addr, ETH_ALEN);
	hdr->ethertype = htons(ETH_P_PAE);

	pos = (u8 *) (hdr + 1);
	os_memcpy(pos, data, data_len);

	res = send(drv->sock, (u8 *) hdr, len, 0);
	os_free(hdr);

	if (res < 0) {
		perror("wired_send_eapol: send");
		printf("wired_send_eapol - packet len: %lu - failed\n",
		       (unsigned long) len);
	}

	return res;
}


static void * wired_driver_hapd_init(struct hostapd_data *hapd,
				     struct wpa_init_params *params)
{
	struct wpa_driver_wiredng_data *drv;

	drv = os_zalloc(sizeof(struct wpa_driver_wiredng_data));
	if (drv == NULL) {
		printf("Could not allocate memory for wired driver data\n");
		return NULL;
	}

	drv->ctx = hapd;
	os_strlcpy(drv->ifname, params->ifname, sizeof(drv->ifname));
	drv->ifidx = linux_ifname2idx(drv->ifname);
	if (drv->ifidx < 0) {
		perror("if_nametoindex");
		return NULL;
	}
	drv->use_pae_group_addr = params->use_pae_group_addr;

	if (wired_init_sockets(drv, params->own_addr)) {
		os_free(drv);
		return NULL;
	}

	return drv;
}


static void wired_driver_hapd_deinit(void *priv)
{
	struct wpa_driver_wiredng_data *drv = priv;

	if (drv->sock >= 0)
		close(drv->sock);
	if (drv->nl)
		netlink_deinit(drv->nl);

	os_free(drv);
}


static int wpa_driver_wiredng_get_ssid(void *priv, u8 *ssid)
{
	ssid[0] = 0;
	return 0;
}


static int wpa_driver_wiredng_get_bssid(void *priv, u8 *bssid)
{
	/* Report PAE group address as the "BSSID" for wired connection. */
	os_memcpy(bssid, pae_group_addr, ETH_ALEN);
	return 0;
}


static int wpa_driver_wiredng_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	os_memset(capa, 0, sizeof(*capa));
	capa->flags = WPA_DRIVER_FLAGS_WIRED;
	return 0;
}


static void wiredng_remove_iface(struct wpa_driver_wiredng_data *drv, int ifidx)
{
	int i, found;

	wpa_printf(MSG_DEBUG, "wiredng: Remove interface ifindex=%d", ifidx);

	if (macvlan_del_interface(ifidx) < 0)
		return;

	/* remove ifidx from drv ifidx list */
	i = 0; found = 0;
	while (i + found < drv->numVlanInterfaces) {
		drv->vlanInterfaceIdx[i] = drv->vlanInterfaceIdx[i+found];
		if (drv->vlanInterfaceIdx[i] == ifidx)
			found++;
		else
			i++;
	}
	drv->numVlanInterfaces -= found;

	i = 0; found = 0;
	while (i + found < drv->numSTA) {
		drv->sta[i] = drv->sta[i + found];
		if (drv->sta[i].ifidx == ifidx) {
			drv_event_disassoc(drv->ctx, drv->sta[i].addr);
			found++;
		} else
			i++;
	}
	drv->numSTA -= found;

        return;
}


static int wpa_driver_wiredng_if_add(void *priv, enum wpa_driver_if_type type,
		      const char *ifname, const u8 *addr, void *bss_ctx,
		      void **drv_priv, char *force_ifname, u8 *if_addr,
		      const char *bridge, int use_existing)
{
	struct wpa_driver_wiredng_data *drv = priv;
	int ret;

	wpa_printf(MSG_DEBUG, "wiredng: Add interface %s to parent %d(%s)", ifname, drv->ifidx, drv->ifname);
	if (linux_ifname2idx(ifname) > 0) {
		if (use_existing) {
			wpa_printf(MSG_DEBUG, "wiredng: Continue using existing interface %s",
				   ifname);
			return -ENFILE;
		}
		wpa_printf(MSG_INFO, "Try to remove and re-create %s", ifname);

		/* Try to remove the interface that was already there. */
		wiredng_remove_iface(drv, linux_ifname2idx(ifname));
	}

	/* Try to create the interface again */
	ret = macvlan_add_interface(drv->ifidx, ifname, "source", NULL);
	if (!ret) {
		/* set new link up */
		linux_set_iface_flags(drv->sock, ifname, 1);

		int* newVlanIfIdx = realloc(drv->vlanInterfaceIdx, (drv->numVlanInterfaces + 1) * sizeof(*(drv->vlanInterfaceIdx)));
		if (newVlanIfIdx) {
			drv->vlanInterfaceIdx = newVlanIfIdx;
			drv->vlanInterfaceIdx[drv->numVlanInterfaces] = linux_ifname2idx(ifname);
			drv->numVlanInterfaces++;
		} else {
			ret = -ENOMEM;
		}
	}

	return ret;
}


static int driver_wiredng_set_sta_vlan(void *priv, const u8 *addr,
				       const char *ifname, int vlan_id)
{
	struct wpa_driver_wiredng_data *drv = priv;
	struct wpa_driver_wiredng_sta *newsta;
	int i;

	for (i = 0; i < drv->numVlanInterfaces; i++) {
		macvlan_interface_change_mac(drv->vlanInterfaceIdx[i], 0, addr);
	}
	macvlan_interface_change_mac(linux_ifname2idx(ifname), 1, addr);

	for (i = 0; i < drv->numSTA; i++) {
		if (memcmp(drv->sta[i].addr,addr,ETH_ALEN) == 0) {
			break;
		}
	}
	if (i  == drv->numSTA) { /* not found */
		newsta = realloc(drv->sta, (drv->numSTA + 1) * sizeof(*newsta));
		if (!newsta)
			return 1;
		drv->sta = newsta;
		drv->numSTA++;

		memcpy(drv->sta[i].addr, addr, ETH_ALEN);
	}

	drv->sta[i].ifidx = linux_ifname2idx(ifname);

	return 0;
}

static int driver_wiredng_if_remove(void *priv, enum wpa_driver_if_type type,
				    const char *ifname)
{
	struct wpa_driver_wiredng_data *drv = priv;

	int ifindex = linux_ifname2idx(ifname);

	wpa_printf(MSG_DEBUG, "wiredng: %s(ifname=%s) ifindex=%d",
		   __func__, ifname, ifindex);

	wiredng_remove_iface(drv, ifindex);
	return 0;
}


static int wpa_driver_wiredng_sta_add(void *priv,
				      struct hostapd_sta_add_params *params)
{
	return 0;
}


static int driver_wiredng_sta_remove(void *priv, const u8 *addr)
{
	struct wpa_driver_wiredng_data *drv = priv;
	int i;
	for (i = 0; i < drv->numVlanInterfaces; i++) {
		macvlan_interface_change_mac(drv->vlanInterfaceIdx[i], 0, addr);
	}
	return 0;
}


const struct wpa_driver_ops wpa_driver_wiredng_ops = {
	.name = "wired-ng",
	.desc = "Wired-ng Ethernet driver",
	.hapd_init = wired_driver_hapd_init,
	.hapd_deinit = wired_driver_hapd_deinit,
	.hapd_send_eapol = wired_send_eapol,
	.get_ssid = wpa_driver_wiredng_get_ssid,
	.get_bssid = wpa_driver_wiredng_get_bssid,
	.get_capa = wpa_driver_wiredng_get_capa,
        .if_add = wpa_driver_wiredng_if_add,
        .if_remove = driver_wiredng_if_remove,
	.sta_add = wpa_driver_wiredng_sta_add,
	.sta_remove = driver_wiredng_sta_remove,
	.set_sta_vlan = driver_wiredng_set_sta_vlan,
	.flush = driver_wiredng_flush,
};

#endif // __LINUX__
#endif // HOSTAPD
