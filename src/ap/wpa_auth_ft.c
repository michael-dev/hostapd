/*
 * hostapd - IEEE 802.11r - Fast BSS Transition
 * Copyright (c) 2004-2015, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "crypto/aes_wrap.h"
#include "crypto/random.h"
#include "ap_config.h"
#include "ieee802_11.h"
#include "wmm.h"
#include "wpa_auth.h"
#include "wpa_auth_i.h"


#ifdef CONFIG_IEEE80211R

static int wpa_ft_rrb_rx_request(struct wpa_authenticator *wpa_auth,
				 const u8 *current_ap, const u8 *sta_addr,
				 const u8 *body, size_t len);
static int wpa_ft_send_rrb_auth_resp(struct wpa_state_machine *sm,
				     const u8 *current_ap, const u8 *sta_addr,
				     u16 status, const u8 *resp_ies,
				     size_t resp_ies_len);
static void ft_pull_resp_cb_finish(void *eloop_ctx, void *timeout_ctx);
void wpa_ft_expire_pull(void *eloop_ctx, void *timeout_ctx);


static int wpa_ft_rrb_send(struct wpa_authenticator *wpa_auth, const u8 *dst,
			   const u8 *data, size_t data_len)
{
	if (wpa_auth->cb.send_ether == NULL)
		return -1;
	wpa_printf(MSG_DEBUG, "FT: RRB send to " MACSTR, MAC2STR(dst));
	return wpa_auth->cb.send_ether(wpa_auth->cb.ctx, dst, ETH_P_RRB,
				       data, data_len);
}


static int wpa_ft_action_send(struct wpa_authenticator *wpa_auth,
			      const u8 *dst, const u8 *data, size_t data_len)
{
	if (wpa_auth->cb.send_ft_action == NULL)
		return -1;
	return wpa_auth->cb.send_ft_action(wpa_auth->cb.ctx, dst,
					   data, data_len);
}


static inline const u8 * wpa_ft_get_psk(struct wpa_authenticator *wpa_auth,
					const u8 *addr, const u8 *p2p_dev_addr,
					const u8 *prev_psk)
{
	if (wpa_auth->cb.get_psk == NULL)
		return NULL;
	return wpa_auth->cb.get_psk(wpa_auth->cb.ctx, addr, p2p_dev_addr,
				    prev_psk);
}


static int
wpa_ft_add_sta(struct wpa_authenticator *wpa_auth, const u8 *sta_addr,
	       struct wpa_state_machine **sm,
	       void (*cb)(void *hapd, const u8 *buf, size_t len, const u8 *mac, int accepted, u32 session_timeout),
	       void *cb_ctx, int cb_ctx_len)
{
	if (wpa_auth->cb.add_sta == NULL) {
		*sm = NULL;
		return 0;
	}
	return wpa_auth->cb.add_sta(wpa_auth->cb.ctx, sta_addr, sm, cb, cb_ctx, cb_ctx_len);
}


static int
wpa_ft_set_vlan(struct wpa_authenticator *wpa_auth, const u8 *sta_addr,
		struct ft_vlan vlan)
{
	if (wpa_auth->cb.set_vlan == NULL)
		return -1;
	return wpa_auth->cb.set_vlan(wpa_auth->cb.ctx, sta_addr, vlan);
}


static int
wpa_ft_get_vlan(struct wpa_authenticator *wpa_auth, const u8 *sta_addr,
		struct ft_vlan *vlan)
{
	if (wpa_auth->cb.get_vlan == NULL)
		return -1;
	return wpa_auth->cb.get_vlan(wpa_auth->cb.ctx, sta_addr, vlan);
}


static int
wpa_ft_get_session_timeout(struct wpa_authenticator *wpa_auth, const u8 *sta_addr)
{
	if (wpa_auth->cb.get_session_timeout == NULL)
		return 0;
	return wpa_auth->cb.get_session_timeout(wpa_auth->cb.ctx, sta_addr);
}


static size_t
wpa_ft_get_identity(struct wpa_authenticator *wpa_auth, const u8 *sta_addr, u8 *buf, size_t buflen)
{
	if (wpa_auth->cb.get_identity == NULL)
		return 0;
	return wpa_auth->cb.get_identity(wpa_auth->cb.ctx, sta_addr, buf, buflen);
}


static size_t
wpa_ft_get_radius_cui(struct wpa_authenticator *wpa_auth, const u8 *sta_addr, u8 *buf, size_t buflen)
{
	if (wpa_auth->cb.get_radius_cui == NULL)
		return 0;
	return wpa_auth->cb.get_radius_cui(wpa_auth->cb.ctx, sta_addr, buf, buflen);
}


static void
wpa_ft_set_session_timeout(struct wpa_authenticator *wpa_auth, const u8 *sta_addr,
		    int session_timeout)
{
	if (wpa_auth->cb.set_session_timeout == NULL)
		return;
	wpa_auth->cb.set_session_timeout(wpa_auth->cb.ctx, sta_addr, session_timeout);
}


static void
wpa_ft_set_identity(struct wpa_authenticator *wpa_auth, const u8 *sta_addr,
		    u8 *identity, size_t identity_len)
{
	if (wpa_auth->cb.set_identity == NULL)
		return;
	wpa_auth->cb.set_identity(wpa_auth->cb.ctx, sta_addr, identity,
				  identity_len);
}


static void
wpa_ft_set_radius_cui(struct wpa_authenticator *wpa_auth, const u8 *sta_addr,
		      u8 *radius_cui, size_t radius_cui_len)
{
	if (wpa_auth->cb.set_radius_cui == NULL)
		return;
	wpa_auth->cb.set_radius_cui(wpa_auth->cb.ctx, sta_addr, radius_cui,
				    radius_cui_len);
}


static int wpa_ft_add_tspec(struct wpa_authenticator *wpa_auth,
			    const u8 *sta_addr,
			    u8 *tspec_ie, size_t tspec_ielen)
{
	if (wpa_auth->cb.add_tspec == NULL) {
		wpa_printf(MSG_DEBUG, "FT: add_tspec is not initialized");
		return -1;
	}
	return wpa_auth->cb.add_tspec(wpa_auth->cb.ctx, sta_addr, tspec_ie,
				      tspec_ielen);
}


int wpa_write_mdie(struct wpa_auth_config *conf, u8 *buf, size_t len)
{
	u8 *pos = buf;
	u8 capab;
	if (len < 2 + sizeof(struct rsn_mdie))
		return -1;

	*pos++ = WLAN_EID_MOBILITY_DOMAIN;
	*pos++ = MOBILITY_DOMAIN_ID_LEN + 1;
	os_memcpy(pos, conf->mobility_domain, MOBILITY_DOMAIN_ID_LEN);
	pos += MOBILITY_DOMAIN_ID_LEN;
	capab = 0;
	if (conf->ft_over_ds)
		capab |= RSN_FT_CAPAB_FT_OVER_DS;
	*pos++ = capab;

	return pos - buf;
}


int wpa_write_ftie(struct wpa_auth_config *conf, const u8 *r0kh_id,
		   size_t r0kh_id_len,
		   const u8 *anonce, const u8 *snonce,
		   u8 *buf, size_t len, const u8 *subelem,
		   size_t subelem_len)
{
	u8 *pos = buf, *ielen;
	struct rsn_ftie *hdr;

	if (len < 2 + sizeof(*hdr) + 2 + FT_R1KH_ID_LEN + 2 + r0kh_id_len +
	    subelem_len)
		return -1;

	*pos++ = WLAN_EID_FAST_BSS_TRANSITION;
	ielen = pos++;

	hdr = (struct rsn_ftie *) pos;
	os_memset(hdr, 0, sizeof(*hdr));
	pos += sizeof(*hdr);
	WPA_PUT_LE16(hdr->mic_control, 0);
	if (anonce)
		os_memcpy(hdr->anonce, anonce, WPA_NONCE_LEN);
	if (snonce)
		os_memcpy(hdr->snonce, snonce, WPA_NONCE_LEN);

	/* Optional Parameters */
	*pos++ = FTIE_SUBELEM_R1KH_ID;
	*pos++ = FT_R1KH_ID_LEN;
	os_memcpy(pos, conf->r1_key_holder, FT_R1KH_ID_LEN);
	pos += FT_R1KH_ID_LEN;

	if (r0kh_id) {
		*pos++ = FTIE_SUBELEM_R0KH_ID;
		*pos++ = r0kh_id_len;
		os_memcpy(pos, r0kh_id, r0kh_id_len);
		pos += r0kh_id_len;
	}

	if (subelem) {
		os_memcpy(pos, subelem, subelem_len);
		pos += subelem_len;
	}

	*ielen = pos - buf - 2;

	return pos - buf;
}


struct wpa_ft_pmk_r0_sa {
	struct dl_list list;
	u8 pmk_r0[PMK_LEN];
	u8 pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 spa[ETH_ALEN];
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	struct ft_vlan vlan;
	os_time_t expiration; /* 0 for no expiration */
	os_time_t session_timeout; /* 0 for no expiration */
	u8 identity[FT_IDENTITY_LEN];
	u8 identity_len;
	u8 radius_cui[FT_RADIUS_CUI_LEN];
	u8 radius_cui_len;
	/* TODO: radius_class, EAP type */
	int pmk_r1_pushed;
};

struct wpa_ft_pmk_r1_sa {
	struct dl_list list;
	u8 pmk_r1[PMK_LEN];
	u8 pmk_r1_name[WPA_PMK_NAME_LEN];
	u8 spa[ETH_ALEN];
	int pairwise; /* Pairwise cipher suite, WPA_CIPHER_* */
	struct ft_vlan vlan;
	u8 identity[FT_IDENTITY_LEN];
	u8 identity_len;
	u8 radius_cui[FT_RADIUS_CUI_LEN];
	u8 radius_cui_len;
	os_time_t session_timeout; /* 0 for no expiration */
	/* TODO: radius_class, EAP type */
};

struct wpa_ft_pmk_cache {
	struct dl_list pmk_r0;
	struct dl_list pmk_r1;
};


void wpa_ft_free_pmk_r0(struct wpa_ft_pmk_r0_sa *r0);
void wpa_ft_expire_pmk_r0(void *eloop_ctx, void *timeout_ctx);
void wpa_ft_free_pmk_r1(struct wpa_ft_pmk_r1_sa *r1);
void wpa_ft_expire_pmk_r1(void *eloop_ctx, void *timeout_ctx);

void wpa_ft_free_pmk_r0(struct wpa_ft_pmk_r0_sa *r0)
{
	if (!r0)
		return;

	dl_list_del(&r0->list);
	eloop_cancel_timeout(wpa_ft_expire_pmk_r0, r0, NULL);

	os_memset(r0->pmk_r0, 0, PMK_LEN);
	os_free(r0);
}


void wpa_ft_expire_pmk_r0(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_ft_pmk_r0_sa *r0 = eloop_ctx;
	struct os_reltime now;
	int expiresIn;
	int session_timeout;

	os_get_reltime(&now);

	if (!r0)
		return;

	expiresIn = r0->expiration - now.sec;
	session_timeout = r0->session_timeout - now.sec;

	if ( (!r0->expiration || expiresIn > 0) &&
	     (!r0->session_timeout || session_timeout > 0) ) {
		wpa_printf(MSG_ERROR, "FT: wpa_ft_expire_pmk_r0 called for "
				      "non-expired entry %p, delete in %ds",
				      r0, expiresIn);
		eloop_cancel_timeout(wpa_ft_expire_pmk_r0, r0, NULL);
		eloop_register_timeout(expiresIn + 1, 0,
				       wpa_ft_expire_pmk_r0, r0, NULL);
		if (r0->session_timeout)
			eloop_register_timeout(session_timeout + 1, 0,
					       wpa_ft_expire_pmk_r0, r0, NULL);
		return;
	}

	wpa_ft_free_pmk_r0(r0);
}


void wpa_ft_free_pmk_r1(struct wpa_ft_pmk_r1_sa *r1)
{
	if (!r1)
		return;

	dl_list_del(&r1->list);
	eloop_cancel_timeout(wpa_ft_expire_pmk_r1, r1, NULL);

	os_memset(r1->pmk_r1, 0, PMK_LEN);
	os_free(r1);
}


void wpa_ft_expire_pmk_r1(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_ft_pmk_r1_sa *r1 = eloop_ctx;
	wpa_ft_free_pmk_r1(r1);
}


struct wpa_ft_pmk_cache * wpa_ft_pmk_cache_init(void)
{
	struct wpa_ft_pmk_cache *cache;

	cache = os_zalloc(sizeof(*cache));
	dl_list_init(&cache->pmk_r0);
	dl_list_init(&cache->pmk_r1);

	return cache;
}


void wpa_ft_pmk_cache_deinit(struct wpa_ft_pmk_cache *cache)
{
	struct wpa_ft_pmk_r0_sa *r0, *r0prev;
	struct wpa_ft_pmk_r1_sa *r1, *r1prev;

	dl_list_for_each_safe(r0, r0prev, &cache->pmk_r0,
			      struct wpa_ft_pmk_r0_sa, list) {
		wpa_ft_free_pmk_r0(r0);
	}

	dl_list_for_each_safe(r1, r1prev, &cache->pmk_r1,
			      struct wpa_ft_pmk_r1_sa, list) {
		wpa_ft_free_pmk_r1(r1);
	}

	os_free(cache);
}


static int wpa_ft_store_pmk_r0(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r0,
			       const u8 *pmk_r0_name, int pairwise,
			       const struct ft_vlan vlan,
			       const int expiresIn, const int session_timeout,
			       const u8* identity, u8 identity_len,
			       const u8* radius_cui, u8 radius_cui_len)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r0_sa *r0;
	struct os_reltime now;

	/* TODO: add limit on number of entries in cache */
	os_get_reltime(&now);

	r0 = os_zalloc(sizeof(*r0));
	if (r0 == NULL)
		return -1;

	os_memcpy(r0->pmk_r0, pmk_r0, PMK_LEN);
	os_memcpy(r0->pmk_r0_name, pmk_r0_name, WPA_PMK_NAME_LEN);
	os_memcpy(r0->spa, spa, ETH_ALEN);
	r0->pairwise = pairwise;
	os_memcpy(&r0->vlan, &vlan, FT_VLAN_DATA_LEN);
	if (expiresIn > 0)
		r0->expiration = now.sec + expiresIn;
	if (session_timeout > 0)
		r0->session_timeout = now.sec + session_timeout;
	if (identity && identity_len <= FT_IDENTITY_LEN) {
		os_memcpy(r0->identity, identity, identity_len);
		r0->identity_len = identity_len;
	}
	if (radius_cui && radius_cui_len <= FT_RADIUS_CUI_LEN) {
		os_memcpy(r0->radius_cui, radius_cui, radius_cui_len);
		r0->radius_cui_len = radius_cui_len;
	}

	dl_list_add(&cache->pmk_r0, &r0->list);

	if (expiresIn > 0)
		eloop_register_timeout(expiresIn + 1, 0,
				       wpa_ft_expire_pmk_r0, r0, NULL);
	if (session_timeout > 0)
		eloop_register_timeout(session_timeout + 1, 0,
				       wpa_ft_expire_pmk_r0, r0, NULL);

	return 0;
}


/*
 * identity and radius_cui need to be FT_IDENTITY_LEN / FT_RADIUS_CUI_LEN big
 * at least
 */
static int wpa_ft_fetch_pmk_r0(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r0_name,
			       u8 *pmk_r0, int *pairwise,
			       struct ft_vlan *vlan, int *expiresIn,
			       int *session_timeout,
			       u8 *identity, u8 *identity_len,
			       u8 *radius_cui, u8 *radius_cui_len)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r0_sa *r0;
	struct os_reltime now;
	os_get_reltime(&now);

	dl_list_for_each(r0, &cache->pmk_r0, struct wpa_ft_pmk_r0_sa, list) {
		if (os_memcmp(r0->spa, spa, ETH_ALEN) == 0 &&
		    os_memcmp_const(r0->pmk_r0_name, pmk_r0_name,
				    WPA_PMK_NAME_LEN) == 0) {
			os_memcpy(pmk_r0, r0->pmk_r0, PMK_LEN);
			if (pairwise)
				*pairwise = r0->pairwise;
			if (vlan)
				os_memcpy(vlan, &r0->vlan, FT_VLAN_DATA_LEN);
			if (expiresIn && r0->expiration > now.sec)
				*expiresIn = r0->expiration - now.sec;
			else if (expiresIn && r0->expiration)
				*expiresIn = 1;
			else
				*expiresIn = 0;
			if (session_timeout && r0->session_timeout > now.sec)
				*session_timeout = r0->session_timeout - now.sec;
			else if (session_timeout && r0->session_timeout)
				*session_timeout = 1;
			else
				*session_timeout = 0;
			if (identity && identity_len) {
				os_memcpy(identity, r0->identity,
					  r0->identity_len);
				*identity_len = r0->identity_len;
			}
			if (radius_cui && radius_cui_len) {
				os_memcpy(radius_cui, r0->radius_cui,
					  r0->radius_cui_len);
				*radius_cui_len = r0->radius_cui_len;
			}

			return 0;
		}
	}

	return -1;
}


static int wpa_ft_store_pmk_r1(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r1,
			       const u8 *pmk_r1_name, int pairwise,
			       const struct ft_vlan vlan,
			       int expiresIn, const int session_timeout,
			       const u8* identity, u8 identity_len,
			       const u8* radius_cui, u8 radius_cui_len)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	int maxExpiresIn = wpa_auth->conf.r1_max_key_lifetime;
	struct wpa_ft_pmk_r1_sa *r1;
	struct os_reltime now;

	/* TODO: add expiration and limit on number of entries in cache */
	os_get_reltime(&now);

	if (maxExpiresIn && maxExpiresIn < expiresIn)
		expiresIn = maxExpiresIn;

	r1 = os_zalloc(sizeof(*r1));
	if (r1 == NULL)
		return -1;

	os_memcpy(r1->pmk_r1, pmk_r1, PMK_LEN);
	os_memcpy(r1->pmk_r1_name, pmk_r1_name, WPA_PMK_NAME_LEN);
	os_memcpy(r1->spa, spa, ETH_ALEN);
	r1->pairwise = pairwise;
	os_memcpy(&r1->vlan, &vlan, FT_VLAN_DATA_LEN);
	if (identity && identity_len <= FT_IDENTITY_LEN) {
		os_memcpy(r1->identity, identity, identity_len);
		r1->identity_len = identity_len;
	}
	if (radius_cui && radius_cui_len <= FT_RADIUS_CUI_LEN) {
		os_memcpy(r1->radius_cui, radius_cui, radius_cui_len);
		r1->radius_cui_len = radius_cui_len;
	}
	if (session_timeout > 0)
		r1->session_timeout = now.sec + session_timeout;

	dl_list_add(&cache->pmk_r1, &r1->list);

	if (expiresIn > 0)
		eloop_register_timeout(expiresIn + 1, 0,
				       wpa_ft_expire_pmk_r1, r1, NULL);
	if (session_timeout > 0)
		eloop_register_timeout(session_timeout + 1, 0,
				       wpa_ft_expire_pmk_r1, r1, NULL);

	return 0;
}


static int wpa_ft_fetch_pmk_r1(struct wpa_authenticator *wpa_auth,
			       const u8 *spa, const u8 *pmk_r1_name,
			       u8 *pmk_r1, int *pairwise,
			       struct ft_vlan *vlan, int *session_timeout,
			       u8 *identity, u8 *identity_len,
			       u8 *radius_cui, u8 *radius_cui_len)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r1_sa *r1;
	struct os_reltime now;

	os_get_reltime(&now);

	dl_list_for_each(r1, &cache->pmk_r1, struct wpa_ft_pmk_r1_sa, list) {
		if (os_memcmp(r1->spa, spa, ETH_ALEN) == 0 &&
		    os_memcmp_const(r1->pmk_r1_name, pmk_r1_name,
				    WPA_PMK_NAME_LEN) == 0) {
			os_memcpy(pmk_r1, r1->pmk_r1, PMK_LEN);
			if (pairwise)
				*pairwise = r1->pairwise;
			if (vlan)
				os_memcpy(vlan, &r1->vlan, FT_VLAN_DATA_LEN);
			if (session_timeout && r1->session_timeout > now.sec)
				*session_timeout = r1->session_timeout - now.sec;
			else if (session_timeout && r1->session_timeout)
				*session_timeout = 1;
			else
				*session_timeout = 0;
			if (identity && identity_len) {
				os_memcpy(identity, r1->identity,
					  r1->identity_len);
				*identity_len = r1->identity_len;
			}
			if (radius_cui && radius_cui_len) {
				os_memcpy(radius_cui, r1->radius_cui,
					  r1->radius_cui_len);
				*radius_cui_len = r1->radius_cui_len;
			}
			return 0;
		}
	}

	return -1;
}


static void wpa_ft_rrb_del_r0kh(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_authenticator *wpa_auth = eloop_ctx;
	struct ft_remote_r0kh *r0kh, *prev = NULL;

	if (!wpa_auth->conf.r0kh_list)
		return;
	r0kh = *wpa_auth->conf.r0kh_list;
	while (r0kh) {
		if (r0kh != timeout_ctx) {
			r0kh = r0kh->next;
			continue;
		}
		if (prev)
			prev->next = r0kh->next;
		else
			*wpa_auth->conf.r0kh_list = r0kh->next;
		os_free(r0kh);
		break;
	}
}


static void wpa_ft_rrb_add_r0kh(struct wpa_authenticator *wpa_auth,
				struct ft_remote_r0kh *r0kh_wildcard,
				const u8 *src_addr,
				u8 *r0kh_id, size_t id_len, int timeout)
{
	struct ft_remote_r0kh *r0kh;

	if (!wpa_auth->conf.r0kh_list)
		return;

	r0kh = os_zalloc(sizeof(*r0kh));
	if (r0kh == NULL)
		return;

	os_memcpy(r0kh->addr, src_addr, sizeof(r0kh->addr));
	os_memcpy(r0kh->id, r0kh_id, sizeof(r0kh->id));
	r0kh->id_len = id_len;
	if (r0kh_wildcard)
		os_memcpy(r0kh->key, r0kh_wildcard->key, sizeof(r0kh->key));
	r0kh->next = *wpa_auth->conf.r0kh_list;
	*wpa_auth->conf.r0kh_list = r0kh;
	timeout = wpa_auth->conf.rkh_pos_timeout;

	if (timeout > 0)
		eloop_register_timeout(timeout, 0, wpa_ft_rrb_del_r0kh,
				       wpa_auth, r0kh);
}


static void wpa_ft_rrb_del_r1kh(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_authenticator *wpa_auth = eloop_ctx;
	struct ft_remote_r1kh *r1kh, *prev = NULL;

	if (!wpa_auth->conf.r1kh_list)
		return;
	r1kh = *wpa_auth->conf.r1kh_list;
	while (r1kh) {
		if (r1kh != timeout_ctx) {
			r1kh = r1kh->next;
			continue;
		}
		if (prev)
			prev->next = r1kh->next;
		else
			*wpa_auth->conf.r1kh_list = r1kh->next;
		os_free(r1kh);
		break;
	}
}


static void wpa_ft_rrb_add_r1kh(struct wpa_authenticator *wpa_auth,
				struct ft_remote_r1kh *r1kh_wildcard,
				const u8 *src_addr, u8 *r1kh_id, int timeout)
{
	struct ft_remote_r1kh *r1kh;

	if (!wpa_auth->conf.r1kh_list)
		return;

	r1kh = os_zalloc(sizeof(*r1kh));
	if (r1kh == NULL)
		return;

	os_memcpy(r1kh->addr, src_addr, sizeof(r1kh->addr));
	os_memcpy(r1kh->id, r1kh_id, sizeof(r1kh->id));
	os_memcpy(r1kh->key, r1kh_wildcard->key, sizeof(r1kh->key));
	r1kh->next = *wpa_auth->conf.r1kh_list;
	*wpa_auth->conf.r1kh_list = r1kh;

	if (timeout > 0)
		eloop_register_timeout(timeout, 0, wpa_ft_rrb_del_r1kh,
				       wpa_auth, r1kh);
}


void wpa_ft_sta_deinit(struct wpa_state_machine *sm)
{
	eloop_cancel_timeout(wpa_ft_expire_pull, sm, NULL);
}


void wpa_ft_deinit(struct wpa_authenticator *wpa_auth)
{
	eloop_cancel_timeout(wpa_ft_rrb_del_r1kh, wpa_auth, ELOOP_ALL_CTX);
	eloop_cancel_timeout(wpa_ft_rrb_del_r0kh, wpa_auth, ELOOP_ALL_CTX);
}


void wpa_ft_expire_pull(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_state_machine *sm = eloop_ctx;
	if (sm->ft_pending_pull_left_retries <= 0 &&
	    sm->wpa_auth->conf.rkh_neg_timeout) {
		/* final timeout, block this r0kh_id */
		wpa_hexdump(MSG_DEBUG, "FT: Blacklist R0KH-ID",
			    sm->r0kh_id, sm->r0kh_id_len);
		wpa_ft_rrb_add_r0kh(sm->wpa_auth, NULL,
				    (u8*) "\x00\x00\x00\x00\x00\x00",
				    sm->r0kh_id, sm->r0kh_id_len,
				    sm->wpa_auth->conf.rkh_neg_timeout);
	}
	eloop_cancel_timeout(wpa_ft_expire_pull, sm, NULL); /* cancel multiple timeouts */
	ft_pull_resp_cb_finish(eloop_ctx, timeout_ctx);
}


static int wpa_ft_pull_pmk_r1(struct wpa_state_machine *sm,
			      const u8 *ies, size_t ies_len,
			      const u8 *pmk_r0_name)
{
	struct ft_remote_r0kh *r0kh, *r0kh_wildcard = NULL;
	struct ft_r0kh_r1kh_pull_frame frame, f;
	int tsecs, tusecs, first;
	struct wpabuf *ft_pending_req_ies;

	if (sm->ft_pending_pull_left_retries <= 0)
		return -1;
	first = (sm->ft_pending_pull_left_retries ==
		 sm->wpa_auth->conf.rkh_pull_retries);
	sm->ft_pending_pull_left_retries--;

	if (!sm->wpa_auth->conf.r0kh_list)
		return -1;
	r0kh = *sm->wpa_auth->conf.r0kh_list;
	while (r0kh) {
		if (r0kh->id_len == sm->r0kh_id_len &&
		    os_memcmp_const(r0kh->id, sm->r0kh_id, sm->r0kh_id_len) ==
		    0)
			break;
		if (r0kh->id_len == 1 && r0kh->id[0] == '*')
			r0kh_wildcard = r0kh;
		r0kh = r0kh->next;
	}
	if (r0kh == NULL && r0kh_wildcard != NULL) {
		wpa_printf(MSG_DEBUG, "FT: Using wildcard R0KH-ID");
		r0kh = r0kh_wildcard;
	}
	if (r0kh == NULL) {
		wpa_hexdump(MSG_DEBUG, "FT: Did not find R0KH-ID",
			    sm->r0kh_id, sm->r0kh_id_len);
		return -1;
	}
	if (is_zero_ether_addr(r0kh->addr)) {
		wpa_hexdump(MSG_DEBUG, "FT: R0KH-ID is blacklisted",
			    sm->r0kh_id, sm->r0kh_id_len);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "FT: Send PMK-R1 pull request to remote R0KH "
		   "address " MACSTR, MAC2STR(r0kh->addr));

	os_memset(&frame, 0, sizeof(frame));
	frame.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame.packet_type = FT_PACKET_R0KH_R1KH_PULL;
	frame.data_length = host_to_le16(FT_R0KH_R1KH_PULL_DATA_LEN);
	os_memcpy(frame.ap_address, sm->wpa_auth->addr, ETH_ALEN);

	/* aes_wrap() does not support inplace encryption, so use a temporary
	 * buffer for the data. */
	if (first) {
		if (random_get_bytes(f.nonce, FT_R0KH_R1KH_PULL_NONCE_LEN)) {
			wpa_printf(MSG_DEBUG, "FT: Failed to get random data "
					      "for nonce");
			return -1;
		}
		os_memcpy(sm->ft_pending_pull_nonce, f.nonce,
			  FT_R0KH_R1KH_PULL_NONCE_LEN);
	} else
		os_memcpy(f.nonce, sm->ft_pending_pull_nonce,
			  FT_R0KH_R1KH_PULL_NONCE_LEN);
	os_memcpy(f.r0kh_id, sm->r0kh_id, FT_R0KH_ID_MAX_LEN);
	f.r0kh_id_len = sm->r0kh_id_len;
	os_memcpy(f.pmk_r0_name, pmk_r0_name, WPA_PMK_NAME_LEN);
	os_memcpy(f.r1kh_id, sm->wpa_auth->conf.r1_key_holder, FT_R1KH_ID_LEN);
	os_memcpy(f.s1kh_id, sm->addr, ETH_ALEN);
	os_memset(f.pad, 0, sizeof(f.pad));

	if (aes_wrap(r0kh->key, sizeof(r0kh->key),
		     (FT_R0KH_R1KH_PULL_DATA_LEN + 7) / 8,
		     f.nonce, frame.nonce) < 0)
		return -1;

	ft_pending_req_ies = wpabuf_alloc_copy(ies, ies_len);
	wpabuf_free(sm->ft_pending_req_ies);
	sm->ft_pending_req_ies = ft_pending_req_ies;
	if (sm->ft_pending_req_ies == NULL)
		return -1;

	tsecs = sm->wpa_auth->conf.rkh_pull_timeout / 1000;
	tusecs = (sm->wpa_auth->conf.rkh_pull_timeout % 1000) * 1000;
	eloop_register_timeout(tsecs, tusecs, wpa_ft_expire_pull, sm, NULL);

	wpa_ft_rrb_send(sm->wpa_auth, r0kh->addr, (u8 *) &frame, sizeof(frame));

	return 0;
}


int wpa_auth_derive_ptk_ft(struct wpa_state_machine *sm, const u8 *pmk,
			   struct wpa_ptk *ptk)
{
	u8 pmk_r0[PMK_LEN], pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 pmk_r1[PMK_LEN];
	u8 ptk_name[WPA_PMK_NAME_LEN];
	const u8 *mdid = sm->wpa_auth->conf.mobility_domain;
	const u8 *r0kh = sm->wpa_auth->conf.r0_key_holder;
	size_t r0kh_len = sm->wpa_auth->conf.r0_key_holder_len;
	const u8 *r1kh = sm->wpa_auth->conf.r1_key_holder;
	const u8 *ssid = sm->wpa_auth->conf.ssid;
	size_t ssid_len = sm->wpa_auth->conf.ssid_len;
	int psk_local = sm->wpa_auth->conf.ft_psk_generate_local;
	os_time_t expiresIn = sm->wpa_auth->conf.r0_key_lifetime;
	struct ft_vlan vlan;
	u8 identity[FT_IDENTITY_LEN], radius_cui[FT_RADIUS_CUI_LEN];
	int identity_len, radius_cui_len, session_timeout;

	if (sm->xxkey_len == 0) {
		wpa_printf(MSG_DEBUG, "FT: XXKey not available for key "
			   "derivation");
		return -1;
	}

	if (wpa_ft_get_vlan(sm->wpa_auth, sm->addr, &vlan) < 0) {
		wpa_printf(MSG_DEBUG, "FT: vlan not available for STA " MACSTR,
			   MAC2STR(sm->addr));
		return -1;
	}
	session_timeout = wpa_ft_get_session_timeout(sm->wpa_auth, sm->addr);
	identity_len = wpa_ft_get_identity(sm->wpa_auth, sm->addr, identity, sizeof(identity));
	radius_cui_len = wpa_ft_get_radius_cui(sm->wpa_auth, sm->addr, radius_cui, sizeof(radius_cui));

	wpa_derive_pmk_r0(sm->xxkey, sm->xxkey_len, ssid, ssid_len, mdid,
			  r0kh, r0kh_len, sm->addr, pmk_r0, pmk_r0_name);
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R0", pmk_r0, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR0Name", pmk_r0_name, WPA_PMK_NAME_LEN);
	if (!psk_local || !wpa_key_mgmt_ft_psk(sm->wpa_key_mgmt))
		wpa_ft_store_pmk_r0(sm->wpa_auth, sm->addr, pmk_r0,
				    pmk_r0_name, sm->pairwise, vlan, expiresIn,
				    session_timeout, identity, identity_len,
				    radius_cui, radius_cui_len);

	wpa_derive_pmk_r1(pmk_r0, pmk_r0_name, r1kh, sm->addr,
			  pmk_r1, sm->pmk_r1_name);
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1", pmk_r1, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name", sm->pmk_r1_name,
		    WPA_PMK_NAME_LEN);
	if (!psk_local || !wpa_key_mgmt_ft_psk(sm->wpa_key_mgmt))
		wpa_ft_store_pmk_r1(sm->wpa_auth, sm->addr, pmk_r1,
				    sm->pmk_r1_name, sm->pairwise, vlan,
				    expiresIn, session_timeout, identity,
				    identity_len, radius_cui, radius_cui_len);

	return wpa_pmk_r1_to_ptk(pmk_r1, sm->SNonce, sm->ANonce, sm->addr,
				 sm->wpa_auth->addr, sm->pmk_r1_name,
				 ptk, ptk_name, sm->wpa_key_mgmt, sm->pairwise);
}


static inline int wpa_auth_get_seqnum(struct wpa_authenticator *wpa_auth,
				      const u8 *addr, int idx, u8 *seq)
{
	if (wpa_auth->cb.get_seqnum == NULL)
		return -1;
	return wpa_auth->cb.get_seqnum(wpa_auth->cb.ctx, addr, idx, seq);
}


static u8 * wpa_ft_gtk_subelem(struct wpa_state_machine *sm, size_t *len)
{
	u8 *subelem;
	struct wpa_group *gsm = sm->group;
	size_t subelem_len, pad_len;
	const u8 *key;
	size_t key_len;
	u8 keybuf[32];

	key_len = gsm->GTK_len;
	if (key_len > sizeof(keybuf))
		return NULL;

	/*
	 * Pad key for AES Key Wrap if it is not multiple of 8 bytes or is less
	 * than 16 bytes.
	 */
	pad_len = key_len % 8;
	if (pad_len)
		pad_len = 8 - pad_len;
	if (key_len + pad_len < 16)
		pad_len += 8;
	if (pad_len && key_len < sizeof(keybuf)) {
		os_memcpy(keybuf, gsm->GTK[gsm->GN - 1], key_len);
		os_memset(keybuf + key_len, 0, pad_len);
		keybuf[key_len] = 0xdd;
		key_len += pad_len;
		key = keybuf;
	} else
		key = gsm->GTK[gsm->GN - 1];

	/*
	 * Sub-elem ID[1] | Length[1] | Key Info[2] | Key Length[1] | RSC[8] |
	 * Key[5..32].
	 */
	subelem_len = 13 + key_len + 8;
	subelem = os_zalloc(subelem_len);
	if (subelem == NULL)
		return NULL;

	subelem[0] = FTIE_SUBELEM_GTK;
	subelem[1] = 11 + key_len + 8;
	/* Key ID in B0-B1 of Key Info */
	WPA_PUT_LE16(&subelem[2], gsm->GN & 0x03);
	subelem[4] = gsm->GTK_len;
	wpa_auth_get_seqnum(sm->wpa_auth, NULL, gsm->GN, subelem + 5);
	if (aes_wrap(sm->PTK.kek, sm->PTK.kek_len, key_len / 8, key,
		     subelem + 13)) {
		os_free(subelem);
		return NULL;
	}

	*len = subelem_len;
	return subelem;
}


#ifdef CONFIG_IEEE80211W
static u8 * wpa_ft_igtk_subelem(struct wpa_state_machine *sm, size_t *len)
{
	u8 *subelem, *pos;
	struct wpa_group *gsm = sm->group;
	size_t subelem_len;

	/* Sub-elem ID[1] | Length[1] | KeyID[2] | IPN[6] | Key Length[1] |
	 * Key[16+8] */
	subelem_len = 1 + 1 + 2 + 6 + 1 + WPA_IGTK_LEN + 8;
	subelem = os_zalloc(subelem_len);
	if (subelem == NULL)
		return NULL;

	pos = subelem;
	*pos++ = FTIE_SUBELEM_IGTK;
	*pos++ = subelem_len - 2;
	WPA_PUT_LE16(pos, gsm->GN_igtk);
	pos += 2;
	wpa_auth_get_seqnum(sm->wpa_auth, NULL, gsm->GN_igtk, pos);
	pos += 6;
	*pos++ = WPA_IGTK_LEN;
	if (aes_wrap(sm->PTK.kek, sm->PTK.kek_len, WPA_IGTK_LEN / 8,
		     gsm->IGTK[gsm->GN_igtk - 4], pos)) {
		os_free(subelem);
		return NULL;
	}

	*len = subelem_len;
	return subelem;
}
#endif /* CONFIG_IEEE80211W */


static u8 * wpa_ft_process_rdie(struct wpa_state_machine *sm,
				u8 *pos, u8 *end, u8 id, u8 descr_count,
				const u8 *ies, size_t ies_len)
{
	struct ieee802_11_elems parse;
	struct rsn_rdie *rdie;

	wpa_printf(MSG_DEBUG, "FT: Resource Request: id=%d descr_count=%d",
		   id, descr_count);
	wpa_hexdump(MSG_MSGDUMP, "FT: Resource descriptor IE(s)",
		    ies, ies_len);

	if (end - pos < (int) sizeof(*rdie)) {
		wpa_printf(MSG_ERROR, "FT: Not enough room for response RDIE");
		return pos;
	}

	*pos++ = WLAN_EID_RIC_DATA;
	*pos++ = sizeof(*rdie);
	rdie = (struct rsn_rdie *) pos;
	rdie->id = id;
	rdie->descr_count = 0;
	rdie->status_code = host_to_le16(WLAN_STATUS_SUCCESS);
	pos += sizeof(*rdie);

	if (ieee802_11_parse_elems((u8 *) ies, ies_len, &parse, 1) ==
	    ParseFailed) {
		wpa_printf(MSG_DEBUG, "FT: Failed to parse request IEs");
		rdie->status_code =
			host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
		return pos;
	}

	if (parse.wmm_tspec) {
		struct wmm_tspec_element *tspec;

		if (parse.wmm_tspec_len + 2 < (int) sizeof(*tspec)) {
			wpa_printf(MSG_DEBUG, "FT: Too short WMM TSPEC IE "
				   "(%d)", (int) parse.wmm_tspec_len);
			rdie->status_code =
				host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
			return pos;
		}
		if (end - pos < (int) sizeof(*tspec)) {
			wpa_printf(MSG_ERROR, "FT: Not enough room for "
				   "response TSPEC");
			rdie->status_code =
				host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
			return pos;
		}
		tspec = (struct wmm_tspec_element *) pos;
		os_memcpy(tspec, parse.wmm_tspec - 2, sizeof(*tspec));
	}

#ifdef NEED_AP_MLME
	if (parse.wmm_tspec && sm->wpa_auth->conf.ap_mlme) {
		int res;

		res = wmm_process_tspec((struct wmm_tspec_element *) pos);
		wpa_printf(MSG_DEBUG, "FT: ADDTS processing result: %d", res);
		if (res == WMM_ADDTS_STATUS_INVALID_PARAMETERS)
			rdie->status_code =
				host_to_le16(WLAN_STATUS_INVALID_PARAMETERS);
		else if (res == WMM_ADDTS_STATUS_REFUSED)
			rdie->status_code =
				host_to_le16(WLAN_STATUS_REQUEST_DECLINED);
		else {
			/* TSPEC accepted; include updated TSPEC in response */
			rdie->descr_count = 1;
			pos += sizeof(struct wmm_tspec_element);
		}
		return pos;
	}
#endif /* NEED_AP_MLME */

	if (parse.wmm_tspec && !sm->wpa_auth->conf.ap_mlme) {
		int res;

		res = wpa_ft_add_tspec(sm->wpa_auth, sm->addr, pos,
				       sizeof(struct wmm_tspec_element));
		if (res >= 0) {
			if (res)
				rdie->status_code = host_to_le16(res);
			else {
				/* TSPEC accepted; include updated TSPEC in
				 * response */
				rdie->descr_count = 1;
				pos += sizeof(struct wmm_tspec_element);
			}
			return pos;
		}
	}

	wpa_printf(MSG_DEBUG, "FT: No supported resource requested");
	rdie->status_code = host_to_le16(WLAN_STATUS_UNSPECIFIED_FAILURE);
	return pos;
}


static u8 * wpa_ft_process_ric(struct wpa_state_machine *sm, u8 *pos, u8 *end,
			       const u8 *ric, size_t ric_len)
{
	const u8 *rpos, *start;
	const struct rsn_rdie *rdie;

	wpa_hexdump(MSG_MSGDUMP, "FT: RIC Request", ric, ric_len);

	rpos = ric;
	while (rpos + sizeof(*rdie) < ric + ric_len) {
		if (rpos[0] != WLAN_EID_RIC_DATA || rpos[1] < sizeof(*rdie) ||
		    rpos + 2 + rpos[1] > ric + ric_len)
			break;
		rdie = (const struct rsn_rdie *) (rpos + 2);
		rpos += 2 + rpos[1];
		start = rpos;

		while (rpos + 2 <= ric + ric_len &&
		       rpos + 2 + rpos[1] <= ric + ric_len) {
			if (rpos[0] == WLAN_EID_RIC_DATA)
				break;
			rpos += 2 + rpos[1];
		}
		pos = wpa_ft_process_rdie(sm, pos, end, rdie->id,
					  rdie->descr_count,
					  start, rpos - start);
	}

	return pos;
}


u8 * wpa_sm_write_assoc_resp_ies(struct wpa_state_machine *sm, u8 *pos,
				 size_t max_len, int auth_alg,
				 const u8 *req_ies, size_t req_ies_len)
{
	u8 *end, *mdie, *ftie, *rsnie = NULL, *r0kh_id, *subelem = NULL;
	size_t mdie_len, ftie_len, rsnie_len = 0, r0kh_id_len, subelem_len = 0;
	int res;
	struct wpa_auth_config *conf;
	struct rsn_ftie *_ftie;
	struct wpa_ft_ies parse;
	u8 *ric_start;
	u8 *anonce, *snonce;

	if (sm == NULL)
		return pos;

	conf = &sm->wpa_auth->conf;

	if (!wpa_key_mgmt_ft(sm->wpa_key_mgmt))
		return pos;

	end = pos + max_len;

	if (auth_alg == WLAN_AUTH_FT) {
		/*
		 * RSN (only present if this is a Reassociation Response and
		 * part of a fast BSS transition)
		 */
		res = wpa_write_rsn_ie(conf, pos, end - pos, sm->pmk_r1_name);
		if (res < 0)
			return pos;
		rsnie = pos;
		rsnie_len = res;
		pos += res;
	}

	/* Mobility Domain Information */
	res = wpa_write_mdie(conf, pos, end - pos);
	if (res < 0)
		return pos;
	mdie = pos;
	mdie_len = res;
	pos += res;

	/* Fast BSS Transition Information */
	if (auth_alg == WLAN_AUTH_FT) {
		subelem = wpa_ft_gtk_subelem(sm, &subelem_len);
		r0kh_id = sm->r0kh_id;
		r0kh_id_len = sm->r0kh_id_len;
		anonce = sm->ANonce;
		snonce = sm->SNonce;
#ifdef CONFIG_IEEE80211W
		if (sm->mgmt_frame_prot) {
			u8 *igtk;
			size_t igtk_len;
			u8 *nbuf;
			igtk = wpa_ft_igtk_subelem(sm, &igtk_len);
			if (igtk == NULL) {
				os_free(subelem);
				return pos;
			}
			nbuf = os_realloc(subelem, subelem_len + igtk_len);
			if (nbuf == NULL) {
				os_free(subelem);
				os_free(igtk);
				return pos;
			}
			subelem = nbuf;
			os_memcpy(subelem + subelem_len, igtk, igtk_len);
			subelem_len += igtk_len;
			os_free(igtk);
		}
#endif /* CONFIG_IEEE80211W */
	} else {
		r0kh_id = conf->r0_key_holder;
		r0kh_id_len = conf->r0_key_holder_len;
		anonce = NULL;
		snonce = NULL;
	}
	res = wpa_write_ftie(conf, r0kh_id, r0kh_id_len, anonce, snonce, pos,
			     end - pos, subelem, subelem_len);
	os_free(subelem);
	if (res < 0)
		return pos;
	ftie = pos;
	ftie_len = res;
	pos += res;

	os_free(sm->assoc_resp_ftie);
	sm->assoc_resp_ftie = os_malloc(ftie_len);
	if (sm->assoc_resp_ftie)
		os_memcpy(sm->assoc_resp_ftie, ftie, ftie_len);

	_ftie = (struct rsn_ftie *) (ftie + 2);
	if (auth_alg == WLAN_AUTH_FT)
		_ftie->mic_control[1] = 3; /* Information element count */

	ric_start = pos;
	if (wpa_ft_parse_ies(req_ies, req_ies_len, &parse) == 0 && parse.ric) {
		pos = wpa_ft_process_ric(sm, pos, end, parse.ric,
					 parse.ric_len);
		if (auth_alg == WLAN_AUTH_FT)
			_ftie->mic_control[1] +=
				ieee802_11_ie_count(ric_start,
						    pos - ric_start);
	}
	if (ric_start == pos)
		ric_start = NULL;

	if (auth_alg == WLAN_AUTH_FT &&
	    wpa_ft_mic(sm->PTK.kck, sm->PTK.kck_len, sm->addr,
		       sm->wpa_auth->addr, 6,
		       mdie, mdie_len, ftie, ftie_len,
		       rsnie, rsnie_len,
		       ric_start, ric_start ? pos - ric_start : 0,
		       _ftie->mic) < 0)
		wpa_printf(MSG_DEBUG, "FT: Failed to calculate MIC");

	return pos;
}


static inline int wpa_auth_set_key(struct wpa_authenticator *wpa_auth,
				   int vlan_id,
				   enum wpa_alg alg, const u8 *addr, int idx,
				   u8 *key, size_t key_len)
{
	if (wpa_auth->cb.set_key == NULL)
		return -1;
	return wpa_auth->cb.set_key(wpa_auth->cb.ctx, vlan_id, alg, addr, idx,
				    key, key_len);
}


void wpa_ft_install_ptk(struct wpa_state_machine *sm)
{
	enum wpa_alg alg;
	int klen;

	/* MLME-SETKEYS.request(PTK) */
	alg = wpa_cipher_to_alg(sm->pairwise);
	klen = wpa_cipher_key_len(sm->pairwise);
	if (!wpa_cipher_valid_pairwise(sm->pairwise)) {
		wpa_printf(MSG_DEBUG, "FT: Unknown pairwise alg 0x%x - skip "
			   "PTK configuration", sm->pairwise);
		return;
	}

	/* FIX: add STA entry to kernel/driver here? The set_key will fail
	 * most likely without this.. At the moment, STA entry is added only
	 * after association has been completed. This function will be called
	 * again after association to get the PTK configured, but that could be
	 * optimized by adding the STA entry earlier.
	 */
	if (wpa_auth_set_key(sm->wpa_auth, 0, alg, sm->addr, 0,
			     sm->PTK.tk, klen))
		return;

	/* FIX: MLME-SetProtection.Request(TA, Tx_Rx) */
	sm->pairwise_set = TRUE;
}


/* Derive PMK-R1 from PSK, check all available PSK
 */
static int wpa_ft_psk_pmk_r1(struct wpa_state_machine *sm,
			     const u8 *req_pmk_r1_name,
			     u8 *out_pmk_r1, int *out_pairwise,
			     struct ft_vlan *out_vlan, u8 *out_identity,
			     u8 *out_identity_len, u8 *out_radius_cui,
			     u8 *out_radius_cui_len, int *out_session_timeout)
{
	const u8 *pmk = NULL;
	u8 pmk_r0[PMK_LEN], pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 pmk_r1[PMK_LEN], pmk_r1_name[WPA_PMK_NAME_LEN];
	struct wpa_authenticator *wpa_auth = sm->wpa_auth;
	const u8 *mdid = wpa_auth->conf.mobility_domain;
	const u8 *r0kh = sm->r0kh_id;
	size_t r0kh_len = sm->r0kh_id_len;
	const u8 *r1kh = wpa_auth->conf.r1_key_holder;
	const u8 *ssid = wpa_auth->conf.ssid;
	size_t ssid_len = wpa_auth->conf.ssid_len;
	int pairwise;

	pairwise = sm->pairwise;

	for (;;) {
		pmk = wpa_ft_get_psk(wpa_auth, sm->addr, sm->p2p_dev_addr,
				     pmk);
		if (pmk == NULL)
			break;

		wpa_derive_pmk_r0(pmk, PMK_LEN, ssid, ssid_len, mdid,
				  r0kh, r0kh_len, sm->addr, pmk_r0, pmk_r0_name);
		wpa_derive_pmk_r1(pmk_r0, pmk_r0_name, r1kh, sm->addr,
				  pmk_r1, pmk_r1_name);
		if (os_memcmp_const(pmk_r1_name, req_pmk_r1_name,
				    WPA_PMK_NAME_LEN) == 0) {
			/* we found a PSK that matches the request pmk_r1_name */
			wpa_printf(MSG_DEBUG, "FT: found PSK to generate "
					      "PMK_R1 locally");
			os_memcpy(out_pmk_r1, pmk_r1, PMK_LEN);
			if (out_pairwise)
				*out_pairwise = pairwise;
			if (out_vlan &&
			    wpa_ft_get_vlan(sm->wpa_auth, sm->addr,
					    out_vlan) < 0) {
				wpa_printf(MSG_DEBUG, "FT: vlan not available for STA " MACSTR,
					   MAC2STR(sm->addr));
				return -1;
			}
			if (out_identity && out_identity_len)
				*out_identity_len = wpa_ft_get_identity(sm->wpa_auth, sm->addr, out_identity, FT_IDENTITY_LEN);
			if (out_radius_cui && out_radius_cui_len)
				*out_radius_cui_len = wpa_ft_get_radius_cui(sm->wpa_auth, sm->addr, out_radius_cui, FT_RADIUS_CUI_LEN);
			if (out_session_timeout)
				*out_session_timeout = wpa_ft_get_session_timeout(sm->wpa_auth, sm->addr);
			return 0;
		}
	}

	wpa_printf(MSG_DEBUG, "FT: did not find PSK to generate PMK_R1 locally");
	return -1;
}

/* Detect the configuration the station asked for.
 * Required to detect FT-PSK and pairwise cipher. */
static int wpa_ft_set_keymgmt(struct wpa_state_machine *sm,
			      struct wpa_ft_ies *parse)
{
	int key_mgmt, ciphers;

	if (sm->wpa_key_mgmt)
		return 0;

	key_mgmt = parse->key_mgmt & sm->wpa_auth->conf.wpa_key_mgmt;
	if (!key_mgmt) {
		wpa_printf(MSG_DEBUG, "FT: Invalid WPA key mgmt (0x%x) from "
			   MACSTR, parse->key_mgmt, MAC2STR(sm->addr));
		return -1;
	}
	if (key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)
		sm->wpa_key_mgmt = WPA_KEY_MGMT_FT_IEEE8021X;
	else if (key_mgmt & WPA_KEY_MGMT_FT_PSK)
		sm->wpa_key_mgmt = WPA_KEY_MGMT_FT_PSK;
	if (parse->wpa_proto == WPA_PROTO_RSN)
		ciphers = parse->pairwise_cipher & sm->wpa_auth->conf.rsn_pairwise;
	else
		ciphers = parse->pairwise_cipher & sm->wpa_auth->conf.wpa_pairwise;
	if (!ciphers) {
		wpa_printf(MSG_DEBUG, "Invalid %s pairwise cipher (0x%x) "
			   "from " MACSTR,
			   parse->wpa_proto == WPA_PROTO_RSN ? "RSN" : "WPA",
			   parse->pairwise_cipher, MAC2STR(sm->addr));
		return -1;
	}
	sm->pairwise = wpa_pick_pairwise_cipher(ciphers, 0);

	return 0;
}


static int wpa_ft_process_auth_req(struct wpa_state_machine *sm,
				   const u8 *ies, size_t ies_len,
				   u8 **resp_ies, size_t *resp_ies_len)
{
	struct rsn_mdie *mdie;
	struct rsn_ftie *ftie;
	u8 pmk_r1[PMK_LEN], pmk_r1_name[WPA_PMK_NAME_LEN];
	u8 ptk_name[WPA_PMK_NAME_LEN];
	struct wpa_auth_config *conf;
	struct wpa_ft_ies parse;
	size_t buflen;
	int ret;
	u8 *pos, *end;
	int pairwise, session_timeout;
	struct ft_vlan vlan;
	u8 identity[FT_IDENTITY_LEN], radius_cui[FT_RADIUS_CUI_LEN];
	u8 identity_len = 0, radius_cui_len = 0;

	*resp_ies = NULL;
	*resp_ies_len = 0;

	sm->pmk_r1_name_valid = 0;
	conf = &sm->wpa_auth->conf;

	wpa_hexdump(MSG_DEBUG, "FT: Received authentication frame IEs",
		    ies, ies_len);

	if (wpa_ft_parse_ies(ies, ies_len, &parse) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to parse FT IEs");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	mdie = (struct rsn_mdie *) parse.mdie;
	if (mdie == NULL || parse.mdie_len < sizeof(*mdie) ||
	    os_memcmp(mdie->mobility_domain,
		      sm->wpa_auth->conf.mobility_domain,
		      MOBILITY_DOMAIN_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid MDIE");
		return WLAN_STATUS_INVALID_MDIE;
	}

	ftie = (struct rsn_ftie *) parse.ftie;
	if (ftie == NULL || parse.ftie_len < sizeof(*ftie)) {
		wpa_printf(MSG_DEBUG, "FT: Invalid FTIE");
		return WLAN_STATUS_INVALID_FTIE;
	}

	os_memcpy(sm->SNonce, ftie->snonce, WPA_NONCE_LEN);

	if (parse.r0kh_id == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Invalid FTIE - no R0KH-ID");
		return WLAN_STATUS_INVALID_FTIE;
	}

	wpa_hexdump(MSG_DEBUG, "FT: STA R0KH-ID",
		    parse.r0kh_id, parse.r0kh_id_len);
	os_memcpy(sm->r0kh_id, parse.r0kh_id, parse.r0kh_id_len);
	sm->r0kh_id_len = parse.r0kh_id_len;

	if (parse.rsn_pmkid == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No PMKID in RSNIE");
		return WLAN_STATUS_INVALID_PMKID;
	}

	if (wpa_ft_set_keymgmt(sm, &parse) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	wpa_hexdump(MSG_DEBUG, "FT: Requested PMKR0Name",
		    parse.rsn_pmkid, WPA_PMK_NAME_LEN);
	wpa_derive_pmk_r1_name(parse.rsn_pmkid,
			       sm->wpa_auth->conf.r1_key_holder, sm->addr,
			       pmk_r1_name);
	wpa_hexdump(MSG_DEBUG, "FT: Derived requested PMKR1Name",
		    pmk_r1_name, WPA_PMK_NAME_LEN);

	if (conf->ft_psk_generate_local &&
	    wpa_key_mgmt_ft_psk(sm->wpa_key_mgmt)) {
		if (wpa_ft_psk_pmk_r1(sm, pmk_r1_name, pmk_r1, &pairwise,
				      &vlan, identity, &identity_len,
				      radius_cui, &radius_cui_len,
				      &session_timeout) < 0)
			return WLAN_STATUS_INVALID_PMKID;
	} else
	if (wpa_ft_fetch_pmk_r1(sm->wpa_auth, sm->addr, pmk_r1_name, pmk_r1,
		    &pairwise, &vlan, &session_timeout, identity,
		    &identity_len, radius_cui, &radius_cui_len) < 0) {
		if (wpa_ft_pull_pmk_r1(sm, ies, ies_len, parse.rsn_pmkid) < 0) {
			wpa_printf(MSG_DEBUG, "FT: Did not have matching "
				   "PMK-R1 and unknown R0KH-ID");
			return WLAN_STATUS_INVALID_PMKID;
		}

		return -1; /* Status pending */
	}

	wpa_hexdump_key(MSG_DEBUG, "FT: Selected PMK-R1", pmk_r1, PMK_LEN);
	sm->pmk_r1_name_valid = 1;
	os_memcpy(sm->pmk_r1_name, pmk_r1_name, WPA_PMK_NAME_LEN);

	wpa_hexdump(MSG_DEBUG, "FT: Received SNonce",
		    sm->SNonce, WPA_NONCE_LEN);

	if (!sm->ANonceAlreadyPresent) {
		if (random_get_bytes(sm->ANonce, WPA_NONCE_LEN)) {
			wpa_printf(MSG_DEBUG, "FT: Failed to get random data for "
				   "ANonce");
			return WLAN_STATUS_UNSPECIFIED_FAILURE;
		}
		wpa_hexdump(MSG_DEBUG, "FT: Generated ANonce",
			    sm->ANonce, WPA_NONCE_LEN);
		sm->ANonceAlreadyPresent = 1;
	} else {
		wpa_hexdump(MSG_DEBUG, "FT: Reuse ANonce",
			    sm->ANonce, WPA_NONCE_LEN);
	}

	if (wpa_pmk_r1_to_ptk(pmk_r1, sm->SNonce, sm->ANonce, sm->addr,
			      sm->wpa_auth->addr, pmk_r1_name,
			      &sm->PTK, ptk_name, sm->wpa_key_mgmt,
			      pairwise) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	sm->pairwise = pairwise;
	sm->PTK_valid = TRUE;
	wpa_ft_install_ptk(sm);

	if (wpa_ft_set_vlan(sm->wpa_auth, sm->addr, vlan) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to configure VLAN");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	wpa_ft_set_session_timeout(sm->wpa_auth, sm->addr, session_timeout);
	wpa_ft_set_identity(sm->wpa_auth, sm->addr, identity, identity_len);
	wpa_ft_set_radius_cui(sm->wpa_auth, sm->addr, radius_cui, radius_cui_len);

	buflen = 2 + sizeof(struct rsn_mdie) + 2 + sizeof(struct rsn_ftie) +
		2 + FT_R1KH_ID_LEN + 200;
	*resp_ies = os_zalloc(buflen);
	if (*resp_ies == NULL) {
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	pos = *resp_ies;
	end = *resp_ies + buflen;

	ret = wpa_write_rsn_ie(conf, pos, end - pos, parse.rsn_pmkid);
	if (ret < 0) {
		os_free(*resp_ies);
		*resp_ies = NULL;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	pos += ret;

	ret = wpa_write_mdie(conf, pos, end - pos);
	if (ret < 0) {
		os_free(*resp_ies);
		*resp_ies = NULL;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	pos += ret;

	ret = wpa_write_ftie(conf, parse.r0kh_id, parse.r0kh_id_len,
			     sm->ANonce, sm->SNonce, pos, end - pos, NULL, 0);
	if (ret < 0) {
		os_free(*resp_ies);
		*resp_ies = NULL;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}
	pos += ret;

	*resp_ies_len = pos - *resp_ies;

	return WLAN_STATUS_SUCCESS;
}


void wpa_ft_process_auth(struct wpa_state_machine *sm, const u8 *bssid,
			 u16 auth_transaction, const u8 *ies, size_t ies_len,
			 void (*cb)(void *ctx, const u8 *dst, const u8 *bssid,
				    u16 auth_transaction, u16 status,
				    const u8 *ies, size_t ies_len),
			 void *ctx)
{
	u16 status;
	u8 *resp_ies;
	size_t resp_ies_len;
	int res;

	if (sm == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Received authentication frame, but "
			   "WPA SM not available");
		return;
	}

	hostapd_logger(NULL, sm->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		   "FT: Received authentication frame: STA=" MACSTR
		   " BSSID=" MACSTR " transaction=%d",
		   MAC2STR(sm->addr), MAC2STR(bssid), auth_transaction);
	sm->ft_pending_cb = cb;
	sm->ft_pending_cb_ctx = ctx;
	sm->ft_pending_auth_transaction = auth_transaction;
	sm->ft_pending_pull_left_retries = sm->wpa_auth->conf.rkh_pull_retries;
	res = wpa_ft_process_auth_req(sm, ies, ies_len, &resp_ies,
				      &resp_ies_len);
	if (res < 0) {
		hostapd_logger(NULL, sm->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "FT: Callback postponed until response is available");
		return;
	}
	status = res;

	hostapd_logger(NULL, sm->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		   "FT: FT authentication response: dst=" MACSTR
		   " auth_transaction=%d status=%d",
		   MAC2STR(sm->addr), auth_transaction + 1, status);
	wpa_hexdump(MSG_DEBUG, "FT: Response IEs", resp_ies, resp_ies_len);
	cb(ctx, sm->addr, bssid, auth_transaction + 1, status,
	   resp_ies, resp_ies_len);
	os_free(resp_ies);
}


u16 wpa_ft_validate_reassoc(struct wpa_state_machine *sm, const u8 *ies,
			    size_t ies_len)
{
	struct wpa_ft_ies parse;
	struct rsn_mdie *mdie;
	struct rsn_ftie *ftie;
	u8 mic[WPA_EAPOL_KEY_MIC_MAX_LEN];
	size_t mic_len = 16;
	unsigned int count;

	if (sm == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	// station entered ASSOC state, so next AUTH will get new ANonce
	sm->ANonceAlreadyPresent = 0;

	wpa_hexdump(MSG_DEBUG, "FT: Reassoc Req IEs", ies, ies_len);

	if (wpa_ft_parse_ies(ies, ies_len, &parse) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to parse FT IEs");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (parse.rsn == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No RSNIE in Reassoc Req");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (parse.rsn_pmkid == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No PMKID in RSNIE");
		return WLAN_STATUS_INVALID_PMKID;
	}

	if (os_memcmp_const(parse.rsn_pmkid, sm->pmk_r1_name, WPA_PMK_NAME_LEN)
	    != 0) {
		wpa_printf(MSG_DEBUG, "FT: PMKID in Reassoc Req did not match "
			   "with the PMKR1Name derived from auth request");
		return WLAN_STATUS_INVALID_PMKID;
	}

	mdie = (struct rsn_mdie *) parse.mdie;
	if (mdie == NULL || parse.mdie_len < sizeof(*mdie) ||
	    os_memcmp(mdie->mobility_domain,
		      sm->wpa_auth->conf.mobility_domain,
		      MOBILITY_DOMAIN_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid MDIE");
		return WLAN_STATUS_INVALID_MDIE;
	}

	ftie = (struct rsn_ftie *) parse.ftie;
	if (ftie == NULL || parse.ftie_len < sizeof(*ftie)) {
		wpa_printf(MSG_DEBUG, "FT: Invalid FTIE");
		return WLAN_STATUS_INVALID_FTIE;
	}

	if (os_memcmp(ftie->snonce, sm->SNonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: SNonce mismatch in FTIE");
		wpa_hexdump(MSG_DEBUG, "FT: Received SNonce",
			    ftie->snonce, WPA_NONCE_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: Expected SNonce",
			    sm->SNonce, WPA_NONCE_LEN);
		return -1;
	}

	if (os_memcmp(ftie->anonce, sm->ANonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: ANonce mismatch in FTIE");
		wpa_hexdump(MSG_DEBUG, "FT: Received ANonce",
			    ftie->anonce, WPA_NONCE_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: Expected ANonce",
			    sm->ANonce, WPA_NONCE_LEN);
		return -1;
	}


	if (parse.r0kh_id == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No R0KH-ID subelem in FTIE");
		return -1;
	}

	if (parse.r0kh_id_len != sm->r0kh_id_len ||
	    os_memcmp_const(parse.r0kh_id, sm->r0kh_id, parse.r0kh_id_len) != 0)
	{
		wpa_printf(MSG_DEBUG, "FT: R0KH-ID in FTIE did not match with "
			   "the current R0KH-ID");
		wpa_hexdump(MSG_DEBUG, "FT: R0KH-ID in FTIE",
			    parse.r0kh_id, parse.r0kh_id_len);
		wpa_hexdump(MSG_DEBUG, "FT: The current R0KH-ID",
			    sm->r0kh_id, sm->r0kh_id_len);
		return -1;
	}

	if (parse.r1kh_id == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No R1KH-ID subelem in FTIE");
		return -1;
	}

	if (os_memcmp_const(parse.r1kh_id, sm->wpa_auth->conf.r1_key_holder,
			    FT_R1KH_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Unknown R1KH-ID used in "
			   "ReassocReq");
		wpa_hexdump(MSG_DEBUG, "FT: R1KH-ID in FTIE",
			    parse.r1kh_id, FT_R1KH_ID_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: Expected R1KH-ID",
			    sm->wpa_auth->conf.r1_key_holder, FT_R1KH_ID_LEN);
		return -1;
	}

	if (parse.rsn_pmkid == NULL ||
	    os_memcmp_const(parse.rsn_pmkid, sm->pmk_r1_name, WPA_PMK_NAME_LEN))
	{
		wpa_printf(MSG_DEBUG, "FT: No matching PMKR1Name (PMKID) in "
			   "RSNIE (pmkid=%d)", !!parse.rsn_pmkid);
		return -1;
	}

	count = 3;
	if (parse.ric)
		count += ieee802_11_ie_count(parse.ric, parse.ric_len);
	if (ftie->mic_control[1] != count) {
		wpa_printf(MSG_DEBUG, "FT: Unexpected IE count in MIC "
			   "Control: received %u expected %u",
			   ftie->mic_control[1], count);
		return -1;
	}

	if (wpa_ft_mic(sm->PTK.kck, sm->PTK.kck_len, sm->addr,
		       sm->wpa_auth->addr, 5,
		       parse.mdie - 2, parse.mdie_len + 2,
		       parse.ftie - 2, parse.ftie_len + 2,
		       parse.rsn - 2, parse.rsn_len + 2,
		       parse.ric, parse.ric_len,
		       mic) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to calculate MIC");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (os_memcmp_const(mic, ftie->mic, mic_len) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid MIC in FTIE");
		wpa_printf(MSG_DEBUG, "FT: addr=" MACSTR " auth_addr=" MACSTR,
			   MAC2STR(sm->addr), MAC2STR(sm->wpa_auth->addr));
		wpa_hexdump(MSG_MSGDUMP, "FT: Received MIC",
			    ftie->mic, mic_len);
		wpa_hexdump(MSG_MSGDUMP, "FT: Calculated MIC", mic, mic_len);
		wpa_hexdump(MSG_MSGDUMP, "FT: MDIE",
			    parse.mdie - 2, parse.mdie_len + 2);
		wpa_hexdump(MSG_MSGDUMP, "FT: FTIE",
			    parse.ftie - 2, parse.ftie_len + 2);
		wpa_hexdump(MSG_MSGDUMP, "FT: RSN",
			    parse.rsn - 2, parse.rsn_len + 2);
		return WLAN_STATUS_INVALID_FTIE;
	}

	return WLAN_STATUS_SUCCESS;
}


int wpa_ft_action_rx(struct wpa_state_machine *sm, const u8 *data, size_t len)
{
	const u8 *sta_addr, *target_ap;
	const u8 *ies;
	size_t ies_len;
	u8 action;
	struct ft_rrb_frame *frame;

	if (sm == NULL)
		return -1;

	/*
	 * data: Category[1] Action[1] STA_Address[6] Target_AP_Address[6]
	 * FT Request action frame body[variable]
	 */

	if (len < 14) {
		wpa_printf(MSG_DEBUG, "FT: Too short FT Action frame "
			   "(len=%lu)", (unsigned long) len);
		return -1;
	}

	action = data[1];
	sta_addr = data + 2;
	target_ap = data + 8;
	ies = data + 14;
	ies_len = len - 14;

	wpa_printf(MSG_DEBUG, "FT: Received FT Action frame (STA=" MACSTR
		   " Target AP=" MACSTR " Action=%d)",
		   MAC2STR(sta_addr), MAC2STR(target_ap), action);

	if (os_memcmp(sta_addr, sm->addr, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: Mismatch in FT Action STA address: "
			   "STA=" MACSTR " STA-Address=" MACSTR,
			   MAC2STR(sm->addr), MAC2STR(sta_addr));
		return -1;
	}

	/*
	 * Do some sanity checking on the target AP address (not own and not
	 * broadcast. This could be extended to filter based on a list of known
	 * APs in the MD (if such a list were configured).
	 */
	if ((target_ap[0] & 0x01) ||
	    os_memcmp(target_ap, sm->wpa_auth->addr, ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG, "FT: Invalid Target AP in FT Action "
			   "frame");
		return -1;
	}

	wpa_hexdump(MSG_MSGDUMP, "FT: Action frame body", ies, ies_len);

	/* RRB - Forward action frame to the target AP */
	frame = os_malloc(sizeof(*frame) + len);
	if (frame == NULL)
		return -1;
	frame->frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame->packet_type = FT_PACKET_REQUEST;
	frame->action_length = host_to_le16(len);
	os_memcpy(frame->ap_address, sm->wpa_auth->addr, ETH_ALEN);
	os_memcpy(frame + 1, data, len);

	wpa_ft_rrb_send(sm->wpa_auth, target_ap, (u8 *) frame,
			sizeof(*frame) + len);
	os_free(frame);

	return 0;
}


static void wpa_ft_rrb_rx_request_cb(void *ctx, const u8 *dst, const u8 *bssid,
				     u16 auth_transaction, u16 resp,
				     const u8 *ies, size_t ies_len)
{
	struct wpa_state_machine *sm = ctx;
	wpa_printf(MSG_DEBUG, "FT: Over-the-DS RX request cb for " MACSTR,
		   MAC2STR(sm->addr));
	wpa_ft_send_rrb_auth_resp(sm, sm->ft_pending_current_ap, sm->addr,
				  resp, ies, ies_len);
}


struct wpa_ft_rrb_rx_request_restart_ctx {
	struct wpa_authenticator *wpa_auth;
	u8 current_ap[ETH_ALEN];
	u8 sta_addr[ETH_ALEN];
	u8 buf[];
};


static void
wpa_ft_rrb_rx_request_restart_cb(void *hapd, const u8 *buf,
				 size_t len, const u8 *mac, int accepted,
				 u32 session_timeout)
{
	struct wpa_ft_rrb_rx_request_restart_ctx *ctx = (struct wpa_ft_rrb_rx_request_restart_ctx*) buf;

	wpa_ft_rrb_rx_request(ctx->wpa_auth, ctx->current_ap, ctx->sta_addr, ctx->buf, len - sizeof(*ctx));
}

static int wpa_ft_rrb_rx_request(struct wpa_authenticator *wpa_auth,
				 const u8 *current_ap, const u8 *sta_addr,
				 const u8 *body, size_t len)
{
	struct wpa_state_machine *sm = NULL;
	u16 status;
	u8 *resp_ies;
	size_t resp_ies_len;
	int res;
	struct wpa_ft_rrb_rx_request_restart_ctx *cb_ctx;

	cb_ctx = os_zalloc(sizeof(struct wpa_ft_rrb_rx_request_restart_ctx) + len);
	if (cb_ctx == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Failed to allocate "
			   "wpa_ft_rrb_rx_request_restart_ctx");
		return -1;
	}

	cb_ctx->wpa_auth = wpa_auth;
	os_memcpy(cb_ctx->current_ap, current_ap, ETH_ALEN);
	os_memcpy(cb_ctx->sta_addr, sta_addr, ETH_ALEN);
	os_memcpy(cb_ctx->buf, body, len);

	res = wpa_ft_add_sta(wpa_auth, sta_addr, &sm,
			    &wpa_ft_rrb_rx_request_restart_cb, cb_ctx,
			    sizeof(*cb_ctx) + len);
	os_free(cb_ctx); cb_ctx = NULL;
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "FT: No immediate response available - wait for macaddr_acl response");
		return 0;
	}
	if (sm == NULL) {
		wpa_printf(MSG_DEBUG, "FT: Failed to add new STA based on "
			   "RRB Request");
		return -1;
	}

	wpa_hexdump(MSG_MSGDUMP, "FT: RRB Request Frame body", body, len);

	sm->ft_pending_cb = wpa_ft_rrb_rx_request_cb;
	sm->ft_pending_cb_ctx = sm;
	os_memcpy(sm->ft_pending_current_ap, current_ap, ETH_ALEN);
	sm->ft_pending_pull_left_retries = sm->wpa_auth->conf.rkh_pull_retries;
	res = wpa_ft_process_auth_req(sm, body, len, &resp_ies,
				      &resp_ies_len);
	if (res < 0) {
		wpa_printf(MSG_DEBUG, "FT: No immediate response available - wait for pull response");
		return 0;
	}
	status = res;

	res = wpa_ft_send_rrb_auth_resp(sm, current_ap, sta_addr, status,
					resp_ies, resp_ies_len);
	os_free(resp_ies);
	return res;
}


static int wpa_ft_send_rrb_auth_resp(struct wpa_state_machine *sm,
				     const u8 *current_ap, const u8 *sta_addr,
				     u16 status, const u8 *resp_ies,
				     size_t resp_ies_len)
{
	struct wpa_authenticator *wpa_auth = sm->wpa_auth;
	size_t rlen;
	struct ft_rrb_frame *frame;
	u8 *pos;

	wpa_printf(MSG_DEBUG, "FT: RRB authentication response: STA=" MACSTR
		   " CurrentAP=" MACSTR " status=%d",
		   MAC2STR(sm->addr), MAC2STR(current_ap), status);
	wpa_hexdump(MSG_DEBUG, "FT: Response IEs", resp_ies, resp_ies_len);

	/* RRB - Forward action frame response to the Current AP */

	/*
	 * data: Category[1] Action[1] STA_Address[6] Target_AP_Address[6]
	 * Status_Code[2] FT Request action frame body[variable]
	 */
	rlen = 2 + 2 * ETH_ALEN + 2 + resp_ies_len;

	frame = os_malloc(sizeof(*frame) + rlen);
	if (frame == NULL)
		return -1;
	frame->frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame->packet_type = FT_PACKET_RESPONSE;
	frame->action_length = host_to_le16(rlen);
	os_memcpy(frame->ap_address, wpa_auth->addr, ETH_ALEN);
	pos = (u8 *) (frame + 1);
	*pos++ = WLAN_ACTION_FT;
	*pos++ = 2; /* Action: Response */
	os_memcpy(pos, sta_addr, ETH_ALEN);
	pos += ETH_ALEN;
	os_memcpy(pos, wpa_auth->addr, ETH_ALEN);
	pos += ETH_ALEN;
	WPA_PUT_LE16(pos, status);
	pos += 2;
	if (resp_ies)
		os_memcpy(pos, resp_ies, resp_ies_len);

	wpa_ft_rrb_send(wpa_auth, current_ap, (u8 *) frame,
			sizeof(*frame) + rlen);
	os_free(frame);

	return 0;
}


static int wpa_ft_rrb_rx_pull(struct wpa_authenticator *wpa_auth,
			      const u8 *src_addr,
			      const u8 *data, size_t data_len)
{
	struct ft_r0kh_r1kh_pull_frame f;
	const u8 *crypt;
	u8 *plain;
	struct ft_remote_r1kh *r1kh, *r1kh_wildcard = NULL;
	struct ft_r0kh_r1kh_resp_frame resp, r;
	u8 pmk_r0[PMK_LEN];
	int pairwise, expiresIn, session_timeout;

	wpa_printf(MSG_DEBUG, "FT: Received PMK-R1 pull");

	if (data_len < sizeof(f))
		return -1;

	if (!wpa_auth->conf.r1kh_list)
		return -1;
	r1kh = *wpa_auth->conf.r1kh_list;
	while (r1kh) {
		if (os_memcmp(r1kh->addr, src_addr, ETH_ALEN) == 0)
			break;
		if (is_zero_ether_addr(r1kh->addr) &&
		    is_zero_ether_addr(r1kh->id))
			r1kh_wildcard = r1kh;
		r1kh = r1kh->next;
	}
	if (r1kh == NULL && r1kh_wildcard != NULL) {
		wpa_printf(MSG_DEBUG, "FT: Using wildcard R1KH-ID");
		r1kh = r1kh_wildcard;
	}
	if (r1kh == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No matching R1KH address found for "
			   "PMK-R1 pull source address " MACSTR,
			   MAC2STR(src_addr));
		return -1;
	}

	crypt = data + offsetof(struct ft_r0kh_r1kh_pull_frame, nonce);
	os_memset(&f, 0, sizeof(f));
	plain = ((u8 *) &f) + offsetof(struct ft_r0kh_r1kh_pull_frame, nonce);
	/* aes_unwrap() does not support inplace decryption, so use a temporary
	 * buffer for the data. */
	if (aes_unwrap(r1kh->key, sizeof(r1kh->key),
		       (FT_R0KH_R1KH_PULL_DATA_LEN + 7) / 8,
		       crypt, plain) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to decrypt PMK-R1 pull "
			   "request from " MACSTR, MAC2STR(src_addr));
		return -1;
	}

	if (f.r0kh_id_len != wpa_auth->conf.r0_key_holder_len ||
	    os_memcmp_const(f.r0kh_id, wpa_auth->conf.r0_key_holder,
			    f.r0kh_id_len) != 0)
		return -1;

	wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - nonce",
		    f.nonce, sizeof(f.nonce));
	wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - PMKR0Name",
		    f.pmk_r0_name, WPA_PMK_NAME_LEN);
	wpa_printf(MSG_DEBUG, "FT: PMK-R1 pull - R1KH-ID=" MACSTR " S1KH-ID="
		   MACSTR, MAC2STR(f.r1kh_id), MAC2STR(f.s1kh_id));

	if (r1kh == r1kh_wildcard && wpa_auth->conf.rkh_pos_timeout)
		wpa_ft_rrb_add_r1kh(wpa_auth, r1kh_wildcard, src_addr,
				    f.r1kh_id, wpa_auth->conf.rkh_pos_timeout);

	os_memset(&resp, 0, sizeof(resp));
	resp.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	resp.packet_type = FT_PACKET_R0KH_R1KH_RESP;
	resp.data_length = host_to_le16(FT_R0KH_R1KH_RESP_DATA_LEN);
	os_memcpy(resp.ap_address, wpa_auth->addr, ETH_ALEN);

	/* aes_wrap() does not support inplace encryption, so use a temporary
	 * buffer for the data. */
	os_memcpy(r.nonce, f.nonce, sizeof(f.nonce));
	os_memcpy(r.r1kh_id, f.r1kh_id, FT_R1KH_ID_LEN);
	os_memcpy(r.s1kh_id, f.s1kh_id, ETH_ALEN);
	if (wpa_ft_fetch_pmk_r0(wpa_auth, f.s1kh_id, f.pmk_r0_name, pmk_r0,
				&pairwise, &r.vlan, &expiresIn,
				&session_timeout, r.identity, &r.identity_len,
				r.radius_cui, &r.radius_cui_len) < 0) {
		wpa_printf(MSG_DEBUG, "FT: No matching PMKR0Name found for "
			   "PMK-R1 pull");
		r.expiresIn = 0xffff;
	} else {
		wpa_derive_pmk_r1(pmk_r0, f.pmk_r0_name, f.r1kh_id, f.s1kh_id,
				  r.pmk_r1, r.pmk_r1_name);
		wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1", r.pmk_r1, PMK_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name", r.pmk_r1_name,
			    WPA_PMK_NAME_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 - Identity",
				r.identity, r.identity_len);
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 - Cui",
				r.radius_cui, r.radius_cui_len);
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 - vlan %d%s",
			   le_to_host16(r.vlan.untagged),
			   r.vlan.tagged[0] ? "+" : "");
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 - session_timeout %d", session_timeout);
		r.pairwise = host_to_le16(pairwise);
		r.expiresIn = host_to_le16(expiresIn);
		r.session_timeout = host_to_le32(session_timeout);
	}
	os_memset(r.pad, 0, sizeof(r.pad));

	if (aes_wrap(r1kh->key, sizeof(r1kh->key),
		     (FT_R0KH_R1KH_RESP_DATA_LEN + 7) / 8,
		     r.nonce, resp.nonce) < 0) {
		os_memset(pmk_r0, 0, PMK_LEN);
		return -1;
	}

	os_memset(pmk_r0, 0, PMK_LEN);

	wpa_ft_rrb_send(wpa_auth, src_addr, (u8 *) &resp, sizeof(resp));

	return 0;
}


static void ft_pull_resp_cb_finish(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_state_machine *sm = eloop_ctx;
	int res;
	u8 *resp_ies;
	size_t resp_ies_len;
	u16 status;

	res = wpa_ft_process_auth_req(sm, wpabuf_head(sm->ft_pending_req_ies),
				      wpabuf_len(sm->ft_pending_req_ies),
				      &resp_ies, &resp_ies_len);
	if (res < 0) {
		/* this loop is broken by ft_pending_pull_left_retries */
		wpa_printf(MSG_DEBUG, "FT: Callback postponed until response is available");
		return;
	}
	wpabuf_free(sm->ft_pending_req_ies);
	sm->ft_pending_req_ies = NULL;
	status = res;
	wpa_printf(MSG_DEBUG, "FT: Postponed auth callback result for " MACSTR
		   " - status %u", MAC2STR(sm->addr), status);

	sm->ft_pending_cb(sm->ft_pending_cb_ctx, sm->addr, sm->wpa_auth->addr,
			  sm->ft_pending_auth_transaction + 1, status,
			  resp_ies, resp_ies_len);
	os_free(resp_ies);
}


struct ft_pull_resp_cb_ctx {
	struct ft_r0kh_r1kh_resp_frame *frame;
	struct ft_remote_r0kh *r0kh_wildcard;
	u8 src_addr[ETH_ALEN];
};

static int ft_pull_resp_cb(struct wpa_state_machine *sm, void *ctx)
{
	struct ft_pull_resp_cb_ctx *info = ctx;
	struct ft_r0kh_r1kh_resp_frame *frame = info->frame;

	if (os_memcmp(frame->s1kh_id, sm->addr, ETH_ALEN) != 0)
		return 0;
	if (os_memcmp(frame->nonce, sm->ft_pending_pull_nonce,
		      FT_R0KH_R1KH_PULL_NONCE_LEN) != 0)
		return 0;
	if (sm->ft_pending_cb == NULL || sm->ft_pending_req_ies == NULL)
		return 0;

	wpa_printf(MSG_DEBUG, "FT: Response to a pending pull request for "
		   MACSTR " - process from timeout", MAC2STR(sm->addr));

	if (frame->expiresIn == 0xffff)
		sm->ft_pending_pull_left_retries = 0;
	eloop_cancel_timeout(wpa_ft_expire_pull, sm, NULL);

	eloop_register_timeout(0, 0, ft_pull_resp_cb_finish, sm, NULL);

	if (info->r0kh_wildcard && sm->wpa_auth->conf.rkh_pos_timeout)
		wpa_ft_rrb_add_r0kh(sm->wpa_auth, info->r0kh_wildcard,
				    info->src_addr, sm->r0kh_id,
				    sm->r0kh_id_len,
				    sm->wpa_auth->conf.rkh_pos_timeout);

	return 1;
}


static int wpa_ft_rrb_rx_resp(struct wpa_authenticator *wpa_auth,
			      const u8 *src_addr,
			      const u8 *data, size_t data_len)
{
	struct ft_r0kh_r1kh_resp_frame f;
	const u8 *crypt;
	u8 *plain;
	struct ft_remote_r0kh *r0kh, *r0kh_wildcard = NULL;
	int pairwise, res, expiresIn, session_timeout;
	struct ft_pull_resp_cb_ctx ctx;
	os_time_t maxExpiresIn = wpa_auth->conf.r0_key_lifetime;

	wpa_printf(MSG_DEBUG, "FT: Received PMK-R1 pull response");

	if (data_len < sizeof(f))
		return -1;

	if (!wpa_auth->conf.r0kh_list)
		return -1;
	r0kh = *wpa_auth->conf.r0kh_list;
	while (r0kh) {
		if (os_memcmp(r0kh->addr, src_addr, ETH_ALEN) == 0)
			break;
		if (r0kh->id_len == 1 && r0kh->id[0] == '*')
			r0kh_wildcard = r0kh;
		r0kh = r0kh->next;
	}
	if (r0kh == NULL && r0kh_wildcard != NULL) {
		wpa_printf(MSG_DEBUG, "FT: Using wildcard R0KH-ID");
		r0kh = r0kh_wildcard;
	}
	if (r0kh == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No matching R0KH address found for "
			   "PMK-R0 pull response source address " MACSTR,
			   MAC2STR(src_addr));
		return -1;
	}

	crypt = data + offsetof(struct ft_r0kh_r1kh_resp_frame, nonce);
	os_memset(&f, 0, sizeof(f));
	plain = ((u8 *) &f) + offsetof(struct ft_r0kh_r1kh_resp_frame, nonce);
	/* aes_unwrap() does not support inplace decryption, so use a temporary
	 * buffer for the data. */
	if (aes_unwrap(r0kh->key, sizeof(r0kh->key),
		       (FT_R0KH_R1KH_RESP_DATA_LEN + 7) / 8,
		       crypt, plain) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to decrypt PMK-R1 pull "
			   "response from " MACSTR, MAC2STR(src_addr));
		return -1;
	}

	if (os_memcmp_const(f.r1kh_id, wpa_auth->conf.r1_key_holder,
			    FT_R1KH_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 pull response did not use a "
			   "matching R1KH-ID");
		return -1;
	}

	pairwise = le_to_host16(f.pairwise);
	if (f.expiresIn == 0xffff) {
		res = 0;
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - nonce",
			    f.nonce, sizeof(f.nonce));
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 pull - R1KH-ID=" MACSTR
			   " S1KH-ID=" MACSTR " NACK",
			   MAC2STR(f.r1kh_id), MAC2STR(f.s1kh_id));
	} else {
		expiresIn = le_to_host16(f.expiresIn);
		session_timeout = le_to_host32(f.session_timeout);
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - nonce",
			    f.nonce, sizeof(f.nonce));
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 pull - R1KH-ID=" MACSTR
			   " S1KH-ID=" MACSTR " pairwise=0x%x expiresIn=%d",
			   MAC2STR(f.r1kh_id), MAC2STR(f.s1kh_id), pairwise,
			   expiresIn);
		wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1 pull - PMK-R1",
				f.pmk_r1, PMK_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - PMKR1Name",
				f.pmk_r1_name, WPA_PMK_NAME_LEN);
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - Identity",
				f.identity, f.identity_len);
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 pull - session_timeout %d",
				session_timeout);
		wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 pull - Cui",
				f.radius_cui, f.radius_cui_len);
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 pull - vlan %d%s",
			   le_to_host16(f.vlan.untagged),
			   f.vlan.tagged[0] ? "+" : "");

		if (expiresIn <= 0 || expiresIn > maxExpiresIn)
			expiresIn = maxExpiresIn;
		res = wpa_ft_store_pmk_r1(wpa_auth, f.s1kh_id, f.pmk_r1,
					  f.pmk_r1_name, pairwise, f.vlan,
					  expiresIn, session_timeout,
					  f.identity, f.identity_len,
					  f.radius_cui, f.radius_cui_len);
	}

	wpa_printf(MSG_DEBUG, "FT: Look for pending pull request");

	ctx.frame = &f;
	os_memcpy(ctx.src_addr, src_addr, ETH_ALEN);
	ctx.r0kh_wildcard = (r0kh == r0kh_wildcard) ? r0kh_wildcard : NULL;

	wpa_auth_for_each_sta(wpa_auth, ft_pull_resp_cb, &ctx);
	os_memset(f.pmk_r1, 0, PMK_LEN);

	return res ? 0 : -1;
}


static int wpa_ft_rrb_rx_push(struct wpa_authenticator *wpa_auth,
			      const u8 *src_addr,
			      const u8 *data, size_t data_len)
{
	struct ft_r0kh_r1kh_push_frame f;
	const u8 *crypt;
	u8 *plain;
	struct ft_remote_r0kh *r0kh, *r0kh_wildcard = NULL;
	struct os_time now;
	os_time_t tsend;
	int pairwise, expiresIn, session_timeout;
	os_time_t maxExpiresIn = wpa_auth->conf.r0_key_lifetime;

	wpa_printf(MSG_DEBUG, "FT: Received PMK-R1 push");

	if (data_len < sizeof(f))
		return -1;

	if (!wpa_auth->conf.r0kh_list)
		return -1;
	r0kh = *wpa_auth->conf.r0kh_list;
	while (r0kh) {
		if (os_memcmp(r0kh->addr, src_addr, ETH_ALEN) == 0)
			break;
		if (r0kh->id_len == 1 && r0kh->id[0] == '*')
			r0kh_wildcard = r0kh;
		r0kh = r0kh->next;
	}
	if (r0kh == NULL && r0kh_wildcard != NULL) {
		wpa_printf(MSG_DEBUG, "FT: Using wildcard R0KH-ID");
		r0kh = r0kh_wildcard;
	}
	if (r0kh == NULL) {
		wpa_printf(MSG_DEBUG, "FT: No matching R0KH address found for "
			   "PMK-R0 push source address " MACSTR,
			   MAC2STR(src_addr));
		return -1;
	}

	crypt = data + offsetof(struct ft_r0kh_r1kh_push_frame, timestamp);
	os_memset(&f, 0, sizeof(f));
	plain = ((u8 *) &f) + offsetof(struct ft_r0kh_r1kh_push_frame,
				       timestamp);
	/* aes_unwrap() does not support inplace decryption, so use a temporary
	 * buffer for the data. */
	if (aes_unwrap(r0kh->key, sizeof(r0kh->key),
		       (FT_R0KH_R1KH_PUSH_DATA_LEN + 7) / 8,
		       crypt, plain) < 0) {
		wpa_printf(MSG_DEBUG, "FT: Failed to decrypt PMK-R1 push from "
			   MACSTR, MAC2STR(src_addr));
		return -1;
	}

	os_get_time(&now);
	tsend = WPA_GET_LE32(f.timestamp);
	if ((now.sec > tsend && now.sec - tsend > 60) ||
	    (now.sec < tsend && tsend - now.sec > 60)) {
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 push did not have a valid "
			   "timestamp: sender time %d own time %d\n",
			   (int) tsend, (int) now.sec);
		return -1;
	}

	if (os_memcmp_const(f.r1kh_id, wpa_auth->conf.r1_key_holder,
			    FT_R1KH_ID_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "FT: PMK-R1 push did not use a matching "
			   "R1KH-ID (received " MACSTR " own " MACSTR ")",
			   MAC2STR(f.r1kh_id),
			   MAC2STR(wpa_auth->conf.r1_key_holder));
		return -1;
	}

	pairwise = le_to_host16(f.pairwise);
	expiresIn = le_to_host16(f.expiresIn);
	session_timeout = le_to_host16(f.session_timeout);
	wpa_printf(MSG_DEBUG, "FT: PMK-R1 push - R1KH-ID=" MACSTR " S1KH-ID="
		   MACSTR " pairwise=0x%x expiresIn=%d",
		   MAC2STR(f.r1kh_id), MAC2STR(f.s1kh_id), pairwise, expiresIn);
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1 push - PMK-R1",
			f.pmk_r1, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 push - PMKR1Name",
			f.pmk_r1_name, WPA_PMK_NAME_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 push - Identity",
			f.identity, f.identity_len);
	wpa_printf(MSG_DEBUG, "FT: PMK-R1 push - session_timeout %d",
			session_timeout);
	wpa_hexdump(MSG_DEBUG, "FT: PMK-R1 push - Cui",
			f.radius_cui, f.radius_cui_len);
	wpa_printf(MSG_DEBUG, "FT: PMK-R1 push - vlan %d%s", le_to_host16(f.vlan.untagged), f.vlan.tagged[0] ? "+" : "");

	if (expiresIn <= 0 || expiresIn > maxExpiresIn)
		expiresIn = maxExpiresIn;
	wpa_ft_store_pmk_r1(wpa_auth, f.s1kh_id, f.pmk_r1, f.pmk_r1_name,
			    pairwise, f.vlan, expiresIn, session_timeout,
			    f.identity, f.identity_len, f.radius_cui,
			    f.radius_cui_len);
	os_memset(f.pmk_r1, 0, PMK_LEN);

	return 0;
}


int wpa_ft_rrb_rx(struct wpa_authenticator *wpa_auth, const u8 *src_addr,
		  const u8 *data, size_t data_len)
{
	struct ft_rrb_frame *frame;
	u16 alen;
	const u8 *pos, *end, *start;
	u8 action;
	const u8 *sta_addr, *target_ap_addr;

	wpa_printf(MSG_DEBUG, "FT: RRB received frame from remote AP " MACSTR,
		   MAC2STR(src_addr));

	if (data_len < sizeof(*frame)) {
		wpa_printf(MSG_DEBUG, "FT: Too short RRB frame (data_len=%lu)",
			   (unsigned long) data_len);
		return -1;
	}

	pos = data;
	frame = (struct ft_rrb_frame *) pos;
	pos += sizeof(*frame);

	alen = le_to_host16(frame->action_length);
	wpa_printf(MSG_DEBUG, "FT: RRB frame - frame_type=%d packet_type=%d "
		   "action_length=%d ap_address=" MACSTR,
		   frame->frame_type, frame->packet_type, alen,
		   MAC2STR(frame->ap_address));

	if (frame->frame_type != RSN_REMOTE_FRAME_TYPE_FT_RRB) {
		/* Discard frame per IEEE Std 802.11r-2008, 11A.10.3 */
		wpa_printf(MSG_DEBUG, "FT: RRB discarded frame with "
			   "unrecognized type %d", frame->frame_type);
		return -1;
	}

	if (alen > data_len - sizeof(*frame)) {
		wpa_printf(MSG_DEBUG, "FT: RRB frame too short for action "
			   "frame");
		return -1;
	}

	if (frame->packet_type == FT_PACKET_R0KH_R1KH_PULL)
		return wpa_ft_rrb_rx_pull(wpa_auth, src_addr, data, data_len);
	if (frame->packet_type == FT_PACKET_R0KH_R1KH_RESP)
		return wpa_ft_rrb_rx_resp(wpa_auth, src_addr, data, data_len);
	if (frame->packet_type == FT_PACKET_R0KH_R1KH_PUSH)
		return wpa_ft_rrb_rx_push(wpa_auth, src_addr, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "FT: RRB - FT Action frame", pos, alen);

	if (alen < 1 + 1 + 2 * ETH_ALEN) {
		wpa_printf(MSG_DEBUG, "FT: Too short RRB frame (not enough "
			   "room for Action Frame body); alen=%lu",
			   (unsigned long) alen);
		return -1;
	}
	start = pos;
	end = pos + alen;

	if (*pos != WLAN_ACTION_FT) {
		wpa_printf(MSG_DEBUG, "FT: Unexpected Action frame category "
			   "%d", *pos);
		return -1;
	}

	pos++;
	action = *pos++;
	sta_addr = pos;
	pos += ETH_ALEN;
	target_ap_addr = pos;
	pos += ETH_ALEN;
	wpa_printf(MSG_DEBUG, "FT: RRB Action Frame: action=%d sta_addr="
		   MACSTR " target_ap_addr=" MACSTR,
		   action, MAC2STR(sta_addr), MAC2STR(target_ap_addr));

	if (frame->packet_type == FT_PACKET_REQUEST) {
		wpa_printf(MSG_DEBUG, "FT: FT Packet Type - Request");

		if (action != 1) {
			wpa_printf(MSG_DEBUG, "FT: Unexpected Action %d in "
				   "RRB Request", action);
			return -1;
		}

		if (os_memcmp(target_ap_addr, wpa_auth->addr, ETH_ALEN) != 0) {
			wpa_printf(MSG_DEBUG, "FT: Target AP address in the "
				   "RRB Request does not match with own "
				   "address");
			return -1;
		}

		if (wpa_ft_rrb_rx_request(wpa_auth, frame->ap_address,
					  sta_addr, pos, end - pos) < 0)
			return -1;
	} else if (frame->packet_type == FT_PACKET_RESPONSE) {
		u16 status_code;

		if (end - pos < 2) {
			wpa_printf(MSG_DEBUG, "FT: Not enough room for status "
				   "code in RRB Response");
			return -1;
		}
		status_code = WPA_GET_LE16(pos);
		pos += 2;

		wpa_printf(MSG_DEBUG, "FT: FT Packet Type - Response "
			   "(status_code=%d)", status_code);

		if (wpa_ft_action_send(wpa_auth, sta_addr, start, alen) < 0)
			return -1;
	} else {
		wpa_printf(MSG_DEBUG, "FT: RRB discarded frame with unknown "
			   "packet_type %d", frame->packet_type);
		return -1;
	}

	if (end > pos) {
		wpa_hexdump(MSG_DEBUG, "FT: Ignore extra data in end",
			    pos, end - pos);
	}

	return 0;
}


static void wpa_ft_generate_pmk_r1(struct wpa_authenticator *wpa_auth,
				   struct wpa_ft_pmk_r0_sa *pmk_r0,
				   struct ft_remote_r1kh *r1kh,
				   const u8 *s1kh_id, int pairwise,
				   int expiresIn, int session_timeout)
{
	struct ft_r0kh_r1kh_push_frame frame, f;
	struct os_time now;
	const u8 *plain;
	u8 *crypt;

	os_memset(&frame, 0, sizeof(frame));
	frame.frame_type = RSN_REMOTE_FRAME_TYPE_FT_RRB;
	frame.packet_type = FT_PACKET_R0KH_R1KH_PUSH;
	frame.data_length = host_to_le16(FT_R0KH_R1KH_PUSH_DATA_LEN);
	os_memcpy(frame.ap_address, wpa_auth->addr, ETH_ALEN);

	/* aes_wrap() does not support inplace encryption, so use a temporary
	 * buffer for the data. */
	os_memcpy(f.r1kh_id, r1kh->id, FT_R1KH_ID_LEN);
	os_memcpy(f.s1kh_id, s1kh_id, ETH_ALEN);
	os_memcpy(f.pmk_r0_name, pmk_r0->pmk_r0_name, WPA_PMK_NAME_LEN);
	wpa_derive_pmk_r1(pmk_r0->pmk_r0, pmk_r0->pmk_r0_name, r1kh->id,
			  s1kh_id, f.pmk_r1, f.pmk_r1_name);
	wpa_printf(MSG_DEBUG, "FT: R1KH-ID " MACSTR, MAC2STR(r1kh->id));
	wpa_hexdump_key(MSG_DEBUG, "FT: PMK-R1", f.pmk_r1, PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "FT: PMKR1Name", f.pmk_r1_name,
		    WPA_PMK_NAME_LEN);
	os_get_time(&now);
	WPA_PUT_LE32(f.timestamp, now.sec);
	f.pairwise = host_to_le16(pairwise);
	f.vlan = pmk_r0->vlan;
	f.expiresIn = host_to_le16(expiresIn);
	f.session_timeout = host_to_le32(session_timeout);
	os_memcpy(f.identity, pmk_r0->identity, pmk_r0->identity_len);
	f.identity_len = pmk_r0->identity_len;
	os_memcpy(f.radius_cui, pmk_r0->radius_cui, pmk_r0->radius_cui_len);
	f.radius_cui_len = pmk_r0->radius_cui_len;
	os_memset(f.pad, 0, sizeof(f.pad));
	plain = ((const u8 *) &f) + offsetof(struct ft_r0kh_r1kh_push_frame,
					     timestamp);
	crypt = ((u8 *) &frame) + offsetof(struct ft_r0kh_r1kh_push_frame,
					   timestamp);
	if (aes_wrap(r1kh->key, sizeof(r1kh->key),
		     (FT_R0KH_R1KH_PUSH_DATA_LEN + 7) / 8,
		     plain, crypt) < 0)
		return;

	wpa_ft_rrb_send(wpa_auth, r1kh->addr, (u8 *) &frame, sizeof(frame));
}


void wpa_ft_push_pmk_r1(struct wpa_authenticator *wpa_auth, const u8 *addr)
{
	struct wpa_ft_pmk_cache *cache = wpa_auth->ft_pmk_cache;
	struct wpa_ft_pmk_r0_sa *r0, *r0found = NULL;
	struct ft_remote_r1kh *r1kh;
	struct os_reltime now;
	int expiresIn, session_timeout;

	if (!wpa_auth->conf.pmk_r1_push)
		return;
	if (!wpa_auth->conf.r1kh_list)
		return;

	dl_list_for_each(r0, &cache->pmk_r0, struct wpa_ft_pmk_r0_sa, list) {
		if (os_memcmp(r0->spa, addr, ETH_ALEN) == 0) {
			r0found = r0;
			break;
		}
	}

	r0 = r0found;
	if (r0 == NULL || r0->pmk_r1_pushed)
		return;
	r0->pmk_r1_pushed = 1;
	os_get_reltime(&now);
	if (r0->expiration > 0 && r0->expiration > now.sec)
		expiresIn = r0->expiration > now.sec;
	else if (r0->expiration)
		expiresIn = 1;
	else
		expiresIn = 0;
	if (r0->session_timeout > 0 && r0->session_timeout > now.sec)
		session_timeout = r0->session_timeout > now.sec;
	else if (r0->session_timeout)
		session_timeout = 1;
	else
		session_timeout = 0;

	wpa_printf(MSG_DEBUG, "FT: Deriving and pushing PMK-R1 keys to R1KHs "
		   "for STA " MACSTR, MAC2STR(addr));

	for (r1kh = *wpa_auth->conf.r1kh_list; r1kh; r1kh = r1kh->next) {
		if (is_zero_ether_addr(r1kh->addr) ||
		    is_zero_ether_addr(r1kh->id))
			continue;
		wpa_ft_generate_pmk_r1(wpa_auth, r0, r1kh, addr, r0->pairwise,
				       expiresIn, session_timeout);
	}
}

#endif /* CONFIG_IEEE80211R */
