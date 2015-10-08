/*
 * hostapd - Authenticator for IEEE 802.11i RSN pre-authentication
 * Copyright (c) 2004-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#ifdef CONFIG_RSN_PREAUTH

#include "utils/common.h"
#include "utils/eloop.h"
#include "l2_packet/l2_packet.h"
#include "common/wpa_common.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ieee802_1x.h"
#include "sta_info.h"
#include "wpa_auth.h"
#include "preauth_auth.h"
#include "bridge.h"
#include "dummy.h"
#include "ifconfig.h"
#ifdef CONFIG_RSN_PREAUTH_COPY
#include "l2_snoop.h"
#endif /* CONFIG_RSN_PREAUTH_COPY */

#ifndef ETH_P_PREAUTH
#define ETH_P_PREAUTH 0x88C7 /* IEEE 802.11i pre-authentication */
#endif /* ETH_P_PREAUTH */

static const int dot11RSNAConfigPMKLifetime = 43200;

struct rsn_preauth_interface {
	struct rsn_preauth_interface *next;
	struct hostapd_data *hapd;
	struct l2_packet_data *l2;
	char *ifname;
	int ifindex;
};

#ifdef CONFIG_RSN_PREAUTH_COPY
struct rsn_preauth_copy_interface {
	struct l2_snoop_data *l2;
	char ifname[IFNAMSIZ+1];
	struct hostapd_data *hapd;
};


static struct rsn_preauth_copy_interface*
rsn_preauth_snoop_init_cb(struct hostapd_data *hapd, char* ifname,
			  void (*rx_callback)(void *ctx, const u8 *src_addr,
						const u8 *buf, size_t len));
static void rsn_preauth_snoop_from_sta(void *ctx, const u8 *src_addr,
				       const u8 *buf, size_t len);
static void rsn_preauth_snoop_to_sta(void *ctx, const u8 *src_addr,
				     const u8 *buf, size_t len);
#endif /* CONFIG_RSN_PREAUTH_COPY */

static void rsn_preauth_receive(void *ctx, const u8 *src_addr,
				const u8 *buf, size_t len)
{
	struct rsn_preauth_interface *piface = ctx;
	struct hostapd_data *hapd = piface->hapd;
	struct ieee802_1x_hdr *hdr;
	struct sta_info *sta;
	struct l2_ethhdr *ethhdr;

	wpa_printf(MSG_DEBUG, "RSN: receive pre-auth packet "
		   "from interface '%s'", piface->ifname);
	if (len < sizeof(*ethhdr) + sizeof(*hdr)) {
		wpa_printf(MSG_DEBUG, "RSN: too short pre-auth packet "
			   "(len=%lu)", (unsigned long) len);
		return;
	}

	ethhdr = (struct l2_ethhdr *) buf;
	hdr = (struct ieee802_1x_hdr *) (ethhdr + 1);

	if (os_memcmp(ethhdr->h_dest, hapd->own_addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "RSN: pre-auth for foreign address "
			   MACSTR, MAC2STR(ethhdr->h_dest));
		return;
	}

	sta = ap_get_sta(hapd, ethhdr->h_source);
	if (sta && (sta->flags & WLAN_STA_ASSOC)) {
		wpa_printf(MSG_DEBUG, "RSN: pre-auth for already association "
			   "STA " MACSTR, MAC2STR(sta->addr));
		return;
	}
	if (!sta && hdr->type == IEEE802_1X_TYPE_EAPOL_START) {
		sta = ap_sta_add(hapd, ethhdr->h_source);
		if (sta == NULL)
			return;
		sta->flags = WLAN_STA_PREAUTH;

		ieee802_1x_new_station(hapd, sta);
		if (sta->eapol_sm == NULL) {
			ap_free_sta(hapd, sta);
			sta = NULL;
		} else {
			sta->eapol_sm->radius_identifier = -1;
			sta->eapol_sm->portValid = TRUE;
			sta->eapol_sm->flags |= EAPOL_SM_PREAUTH;
		}
	}
	if (sta == NULL)
		return;
	sta->preauth_iface = piface;
	ieee802_1x_receive(hapd, ethhdr->h_source, (u8 *) (ethhdr + 1),
			   len - sizeof(*ethhdr));
}


static int rsn_preauth_iface_add(struct hostapd_data *hapd, const char *ifname)
{
	struct rsn_preauth_interface *piface;
	char dummy_iface[IFNAMSIZ+1];

	wpa_printf(MSG_DEBUG, "RSN pre-auth interface '%s'", ifname);

	if (hapd->conf->rsn_preauth_autoconf_bridge) {
#ifdef CONFIG_LIBNL3_ROUTE
		snprintf(dummy_iface, sizeof(dummy_iface), "pre%s",
			 hapd->conf->iface);
		if (dummy_add(dummy_iface, hapd->own_addr) < 0 ||
		    ifconfig_up(dummy_iface) < 0 ||
		    br_addif(ifname, dummy_iface) < 0)
			wpa_printf(MSG_ERROR, "Failed to add bssid to "
				   "rsn_preauth_interface %s", ifname);
#else
		wpa_printf(MSG_ERROR, "Missing libnl3 - bssid not added to "
			   "rsn_preauth_interface %s", ifname);
#endif /* CONFIG_LIBNL3_ROUTE */
	}

	piface = os_zalloc(sizeof(*piface));
	if (piface == NULL)
		return -1;
	piface->hapd = hapd;

	piface->ifname = os_strdup(ifname);
	if (piface->ifname == NULL) {
		goto fail1;
	}

	piface->l2 = l2_packet_init(piface->ifname, NULL, ETH_P_PREAUTH,
				    rsn_preauth_receive, piface, 1);
	if (piface->l2 == NULL) {
		wpa_printf(MSG_ERROR, "Failed to open register layer 2 access "
			   "to ETH_P_PREAUTH");
		goto fail2;
	}

	piface->next = hapd->preauth_iface;
	hapd->preauth_iface = piface;
	return 0;

fail2:
	os_free(piface->ifname);
fail1:
	os_free(piface);
	return -1;
}


void rsn_preauth_iface_deinit(struct hostapd_data *hapd)
{
	struct hostapd_bss_config *conf = hapd->conf;
	struct rsn_preauth_interface *piface, *prev;
	char dummy_iface[IFNAMSIZ+1];

	piface = hapd->preauth_iface;
	hapd->preauth_iface = NULL;
	while (piface) {
		prev = piface;
		piface = piface->next;
		if (hapd->conf->rsn_preauth_autoconf_bridge) {
#ifdef CONFIG_LIBNL3_ROUTE
			snprintf(dummy_iface, sizeof(dummy_iface), "pre%s",
				 conf->iface);
			ifconfig_down(dummy_iface);
			br_delif(prev->ifname, dummy_iface);
			dummy_del(dummy_iface);
#endif /* CONFIG_LIBNL3_ROUTE */
		}
		l2_packet_deinit(prev->l2);
		os_free(prev->ifname);
		os_free(prev);
	}

#ifdef CONFIG_RSN_PREAUTH_COPY
	rsn_preauth_snoop_deinit(hapd, conf->rsn_preauth_copy_iface,
				 hapd->preauth_copy_iface);
	hapd->preauth_copy_iface = NULL;
	rsn_preauth_snoop_deinit(hapd, conf->iface, hapd->preauth_vlan0);
	hapd->preauth_vlan0 = NULL;
#endif /* CONFIG_RSN_PREAUTH_COPY */
}


int rsn_preauth_iface_init(struct hostapd_data *hapd)
{
	char *tmp, *start, *end;

	if (hapd->conf->rsn_preauth_interfaces == NULL)
		goto skip_preauth_iface_init;

	tmp = os_strdup(hapd->conf->rsn_preauth_interfaces);
	if (tmp == NULL)
		return -1;
	start = tmp;
	for (;;) {
		while (*start == ' ')
			start++;
		if (*start == '\0')
			break;
		end = os_strchr(start, ' ');
		if (end)
			*end = '\0';

		if (rsn_preauth_iface_add(hapd, start)) {
			rsn_preauth_iface_deinit(hapd);
			os_free(tmp);
			return -1;
		}

		if (end)
			start = end + 1;
		else
			break;
	}
	os_free(tmp);

skip_preauth_iface_init:
#ifdef CONFIG_RSN_PREAUTH_COPY
	if (hapd->preauth_copy_iface)
		rsn_preauth_snoop_deinit(hapd,
					 hapd->conf->rsn_preauth_copy_iface,
					 rsn_preauth_snoop_to_sta);

	hapd->preauth_copy_iface = rsn_preauth_snoop_init_cb(hapd,
					   hapd->conf->rsn_preauth_copy_iface,
					   rsn_preauth_snoop_to_sta);
	hapd->preauth_vlan0 = rsn_preauth_snoop_init(hapd, hapd->conf->iface);
#endif /* CONFIG_RSN_PREAUTH_COPY */

	return 0;
}


static void rsn_preauth_finished_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;
	wpa_printf(MSG_DEBUG, "RSN: Removing pre-authentication STA entry for "
		   MACSTR, MAC2STR(sta->addr));
	ap_free_sta(hapd, sta);
}


void rsn_preauth_finished(struct hostapd_data *hapd, struct sta_info *sta,
			  int success)
{
	const u8 *key;
	size_t len;
	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_WPA,
		       HOSTAPD_LEVEL_INFO, "pre-authentication %s",
		       success ? "succeeded" : "failed");

	key = ieee802_1x_get_key(sta->eapol_sm, &len);
	if (len > PMK_LEN)
		len = PMK_LEN;
	if (success && key) {
		if (wpa_auth_pmksa_add_preauth(hapd->wpa_auth, key, len,
					       sta->addr,
					       dot11RSNAConfigPMKLifetime,
					       sta->eapol_sm) == 0) {
			hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_WPA,
				       HOSTAPD_LEVEL_DEBUG,
				       "added PMKSA cache entry (pre-auth)");
		} else {
			hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_WPA,
				       HOSTAPD_LEVEL_DEBUG,
				       "failed to add PMKSA cache entry "
				       "(pre-auth)");
		}
	}

	/*
	 * Finish STA entry removal from timeout in order to avoid freeing
	 * STA data before the caller has finished processing.
	 */
	eloop_register_timeout(0, 0, rsn_preauth_finished_cb, hapd, sta);
}


void rsn_preauth_send(struct hostapd_data *hapd, struct sta_info *sta,
		      u8 *buf, size_t len)
{
	struct rsn_preauth_interface *piface;
	struct l2_ethhdr *ethhdr;

	piface = hapd->preauth_iface;
	while (piface) {
		if (piface == sta->preauth_iface)
			break;
		piface = piface->next;
	}

	if (piface == NULL) {
		wpa_printf(MSG_DEBUG, "RSN: Could not find pre-authentication "
			   "interface for " MACSTR, MAC2STR(sta->addr));
		return;
	}

	ethhdr = os_malloc(sizeof(*ethhdr) + len);
	if (ethhdr == NULL)
		return;

	os_memcpy(ethhdr->h_dest, sta->addr, ETH_ALEN);
	os_memcpy(ethhdr->h_source, hapd->own_addr, ETH_ALEN);
	ethhdr->h_proto = host_to_be16(ETH_P_PREAUTH);
	os_memcpy(ethhdr + 1, buf, len);

	if (l2_packet_send(piface->l2, sta->addr, ETH_P_PREAUTH, (u8 *) ethhdr,
			   sizeof(*ethhdr) + len) < 0) {
		wpa_printf(MSG_ERROR, "Failed to send preauth packet using "
			   "l2_packet_send\n");
	}
	os_free(ethhdr);
}


void rsn_preauth_free_station(struct hostapd_data *hapd, struct sta_info *sta)
{
	eloop_cancel_timeout(rsn_preauth_finished_cb, hapd, sta);
}

#ifdef CONFIG_RSN_PREAUTH_COPY
static struct rsn_preauth_copy_interface*
rsn_preauth_snoop_init_cb(struct hostapd_data *hapd, char* ifname,
			    void (*rx_callback)(void *ctx, const u8 *src_addr,
						const u8 *buf, size_t len))
{
	if (!hapd->conf->rsn_preauth_copy_iface[0])
		return NULL;

	struct rsn_preauth_copy_interface *ctx;

	ctx = os_zalloc(sizeof(*ctx));

	if (ctx == NULL) {
		wpa_printf(MSG_ERROR,
			   "RSN: rsn_preauth_init_cb: Failed to alloc ctx");
		goto fail;
	}

	ifconfig_up(ifname);

	os_strlcpy(ctx->ifname, ifname, sizeof(ctx->ifname));
	ctx->hapd = hapd;
	ctx->l2 = l2_snoop_init(ifname, ETH_P_PREAUTH, rx_callback, ctx);

	if (ctx->l2 == NULL) {
		wpa_printf(MSG_ERROR, "RSN: failed to start L2 snooping on %s,"
			   " error: %s", ifname, strerror(errno));
		goto fail;
	}

	return ctx;
fail:
	if (ctx && ctx->l2)
		l2_snoop_deinit(ctx->l2);
	if (ctx)
		os_free(ctx);
	return NULL;
}

void* rsn_preauth_snoop_init(struct hostapd_data *hapd, char* ifname) {
	return rsn_preauth_snoop_init_cb(hapd, ifname,
					 rsn_preauth_snoop_from_sta);
}

void rsn_preauth_snoop_deinit(struct hostapd_data *hapd, char* ifname,
			      void *ctx_ptr)
{
	struct rsn_preauth_copy_interface *ctx = ctx_ptr;
	wpa_printf(MSG_DEBUG, "RSN: deinit pre-authentification snooping"
			      " on %s", ifname);

	if (ctx && ctx->l2)
		l2_snoop_deinit(ctx->l2);
	if (ctx)
		os_free(ctx);
}


struct rsn_preauth_iter_data {
	struct hostapd_data *src_hapd;
	const u8 *src_addr;
	const u8 *dst;
	const u8 *data;
	size_t data_len;
	const char* dest_iface;
};


static int rsn_preauth_iter(struct hostapd_iface *iface, void *ctx)
{
	struct rsn_preauth_iter_data *idata = ctx;
	struct hostapd_data *hapd;
	size_t j;
	struct rsn_preauth_interface *piface;

	for (j = 0; j < iface->num_bss; j++) {
		hapd = iface->bss[j];
		if (hapd == idata->src_hapd)
			continue;
		if (os_memcmp(hapd->own_addr, idata->dst, ETH_ALEN) != 0)
			continue;
		for (piface = hapd->preauth_iface; piface;
		     piface = piface->next) {
			if (strcmp(piface->ifname, idata->dest_iface) != 0)
				continue;
			wpa_printf(MSG_DEBUG, "RSN: Send preauth data directly"
				   " to locally managed BSS " MACSTR "@%s -> "
				   MACSTR "@%s via %s",
				   MAC2STR(idata->src_addr),
				   idata->src_hapd->conf->iface,
				   MAC2STR(hapd->own_addr), hapd->conf->iface,
				   idata->dest_iface);
			rsn_preauth_receive(piface, idata->src_addr,
					    idata->data, idata->data_len);
			return 1;
		}
	}

	return 0;
}

static void rsn_preauth_snoop_from_sta(void *ctx, const u8 *src_addr,
				       const u8 *buf, size_t len)
{
	struct rsn_preauth_copy_interface *l2ctx;
	struct hostapd_data *hapd;
	struct sta_info *sta;
	struct l2_ethhdr *ethhdr;
	struct rsn_preauth_iter_data idata;

	l2ctx = (struct rsn_preauth_copy_interface*) ctx;
	hapd = l2ctx->hapd;

	if (!hapd->preauth_copy_iface)
		return;

	if (len < sizeof(*ethhdr))
		return;
	ethhdr = (struct l2_ethhdr *) buf;

	sta = ap_get_sta(hapd, ethhdr->h_source);
	if (!sta)
		return;

	wpa_printf(MSG_DEBUG, "RSN: preauth_snoop forward from sta " MACSTR
		   " to ap " MACSTR " on from %s to %s",
		   MAC2STR(ethhdr->h_source), MAC2STR(ethhdr->h_dest),
		   l2ctx->ifname, hapd->preauth_copy_iface->ifname);

	idata.src_hapd = hapd;
	idata.dst = ethhdr->h_dest;
	idata.data = buf;
	idata.data_len = len;
	idata.src_addr = src_addr;
	idata.dest_iface = hapd->conf->rsn_preauth_copy_iface;
	if (hapd->iface->interfaces->for_each_interface(
	    hapd->iface->interfaces, rsn_preauth_iter,
	    &idata))
		return;
	l2_snoop_send(hapd->preauth_copy_iface->l2, buf, len);
}

static void rsn_preauth_snoop_to_sta(void *ctx, const u8 *src_addr,
				     const u8 *buf, size_t len)
{
	struct rsn_preauth_copy_interface *l2ctx;
	struct hostapd_data *hapd;
	struct rsn_preauth_copy_interface *destctx;
	struct hostapd_vlan *vlan;
	struct sta_info *sta;
	struct l2_ethhdr *ethhdr;

	l2ctx = (struct rsn_preauth_copy_interface*) ctx;
	hapd = l2ctx->hapd;

	if (!hapd->preauth_copy_iface)
		return;

	if (len < sizeof(*ethhdr))
		return;
	ethhdr = (struct l2_ethhdr *) buf;

	sta = ap_get_sta(hapd, ethhdr->h_dest);
	if (!sta)
		return;

	destctx = hapd->preauth_vlan0;
#ifndef CONFIG_NO_VLAN
	if (sta->vlan_id_bound) {
		vlan = hapd->conf->vlan;
		while (vlan) {
			if (vlan->vlan_id == sta->vlan_id_bound)
				break;
			vlan = vlan->next;
		}
		if (!vlan)
			return;
		destctx = vlan->rsn_preauth;
	}
#endif /* CONFIG_NO_VLAN */
	if (!destctx || !destctx->l2)
		return;

	wpa_printf(MSG_DEBUG, "RSN: preauth_snoop forward from ap " MACSTR 
		   " to sta " MACSTR " if from %s to %s",
		   MAC2STR(ethhdr->h_source), MAC2STR(ethhdr->h_dest),
		   l2ctx->ifname, destctx->ifname);

	l2_snoop_send(destctx->l2, buf, len);
}
#endif /* CONFIG_RSN_PREAUTH_COPY */

#endif /* CONFIG_RSN_PREAUTH */
