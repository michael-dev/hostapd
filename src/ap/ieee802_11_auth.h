/*
 * hostapd / IEEE 802.11 authentication (ACL)
 * Copyright (c) 2003-2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_11_AUTH_H
#define IEEE802_11_AUTH_H

enum {
	HOSTAPD_ACL_REJECT = 0,
	HOSTAPD_ACL_ACCEPT = 1,
	HOSTAPD_ACL_PENDING = 2,
	HOSTAPD_ACL_ACCEPT_TIMEOUT = 3
};

struct hostapd_allowed_address_info {
	u32 session_timeout;
	u32 acct_interim_interval;
	struct vlan_description vlan_id;
	struct hostapd_sta_wpa_psk_short *psk;
	char *identity;
	char *radius_cui;
};

void hostapd_allowed_address_init(struct hostapd_allowed_address_info *info);
void hostapd_allowed_address_free(struct hostapd_allowed_address_info *info);
int hostapd_allowed_address(struct hostapd_data *hapd, const u8 *addr,
			    const u8 *msg, size_t len,
			    void (*cb) (struct hostapd_data *hapd,
					const u8 *buf, size_t len,
					const u8 *mac, int accepted,
					u32 session_timeout),
			    struct hostapd_allowed_address_info *info);
int hostapd_acl_init(struct hostapd_data *hapd);
void hostapd_acl_deinit(struct hostapd_data *hapd);
void hostapd_free_psk_list(struct hostapd_sta_wpa_psk_short *psk);

#endif /* IEEE802_11_AUTH_H */
