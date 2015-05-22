/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#ifdef CONFIG_FULL_DYNAMIC_VLAN
#include "vlan_if.h"
#ifndef CONFIG_VLAN_ASYNC
#ifndef CONFIG_VLAN_NETLINK
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/if_vlan.h>
#include "vlan_ioctl.h"
#endif /* VLAN_NETLINK */
#else /* VLAN_ASYNC */
#include "netlink/cache.h"
#include "netlink/route/link.h"
#endif /* VLAN_ASYNC */
#include "ifconfig.h"
#endif /* CONFIG_FULL_DYNAMIC_VLAN */

#include "utils/common.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "vlan_init.h"
#include "wpa_auth_glue.h"
#ifdef CONFIG_RSN_PREAUTH_COPY
#include "preauth_auth.h"
#endif /* CONFIG_RSN_PREAUTH_COPY */


#ifdef CONFIG_FULL_DYNAMIC_VLAN


#ifndef CONFIG_VLAN_ASYNC
#include "drivers/netlink.h"
#include "drivers/priv_netlink.h"
#endif /* CONFIG_VLAN_ASYNC */
#include "utils/eloop.h"
#include "vlan_priv.h"


#ifndef CONFIG_VLAN_ASYNC
#include "vlan_sync.h"
#else
#include "vlan_async.h"
#endif


#ifndef CONFIG_VLAN_ASYNC
struct full_dynamic_vlan {
	struct netlink_data * nl;
	struct hapd_interfaces *interfaces;
};

static struct full_dynamic_vlan *full_dynamic_vlan = 0;
#endif /* CONFIG_VLAN_ASYNC */

struct vlan_handle_read_ifname_data {
	char ifname[IFNAMSIZ + 1];
	int del;
};

static int vlan_if_add(struct hostapd_data *hapd, struct hostapd_vlan *vlan,
		       int existsok)
{
	int ret, i;

	for (i = 0; i < 4; i++) {
		if (!hapd->conf->ssid.wep.key[i])
			continue;
		wpa_printf(MSG_ERROR, "VLAN: refusing to set up VLAN iface %s"
			   " with WEP", vlan->ifname);
		return -1;
	}

	if (!vlan_if_nametoindex(vlan->ifname))
		ret = hostapd_vlan_if_add(hapd, vlan->ifname);
	else if (!existsok)
		return -1;
	else
		ret = 0;

	if (ret)
		return ret;

	ifconfig_up(vlan->ifname); /* else wpa group will fail fatal */

 	if (hapd->wpa_auth)
		ret = hostapd_setup_wpa_vlan(hapd, vlan->vlan_id);

	if (ret == 0)
		return ret;

	wpa_printf(MSG_ERROR, "WPA initialization for vlan %d failed (%d)",
		   vlan->vlan_id, ret);
	if (hostapd_desetup_wpa_vlan(hapd, vlan->vlan_id))
		wpa_printf(MSG_ERROR, "WPA deinit of %s failed", vlan->ifname);

	/* group state machine setup failed */
	if (hostapd_vlan_if_remove(hapd, vlan->ifname))
		wpa_printf(MSG_ERROR, "Removal of %s failed", vlan->ifname);

	return ret;
}


int vlan_if_remove(struct hostapd_data *hapd, struct hostapd_vlan *vlan)
{
	int ret;
	ret = hostapd_desetup_wpa_vlan(hapd, vlan->vlan_id);
	if (ret)
		wpa_printf(MSG_ERROR, "WPA deinitialization for vlan %d failed"
			   " (%d)", vlan->vlan_id, ret);

	return hostapd_vlan_if_remove(hapd, vlan->ifname);
}

void vlan_drop_and_free(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	struct hostapd_vlan *first, *curr, *prev;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_drop_and_free(%s)", vlan->ifname);

	if (vlan_if_nametoindex(vlan->ifname) && vlan_if_remove(hapd, vlan))
		wpa_printf(MSG_ERROR, "VLAN: Could not remove VLAN "
			   "iface: %s: %s",
			   vlan->ifname, strerror(errno));


	first = prev = curr = hapd->conf->vlan;
	while (curr) {
		if (curr != vlan) {
			prev = curr;
			curr = curr->next;
			continue;
		}
		if (vlan == first) {
			hapd->conf->vlan = vlan->next;
		} else {
			prev->next = vlan->next;
		}
		os_free(vlan);
		break;
	}
}


static void vlan_newlink_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_vlan *vlan = eloop_ctx;
	struct hostapd_data *hapd = timeout_ctx;

	if (vlan->configured)
		return;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_newlink(%s)", vlan->ifname);

	vlan->configured = 1;

	ifconfig_up(vlan->ifname);

#ifdef CONFIG_RSN_PREAUTH_COPY
	if (!vlan->rsn_preauth)
		vlan->rsn_preauth = rsn_preauth_snoop_init(hapd, vlan->ifname);
#endif /* CONFIG_RSN_PREAUTH_COPY */

	vlan_configure(vlan, hapd);
}


static void vlan_dellink_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_vlan *vlan = eloop_ctx;
	struct hostapd_data *hapd = timeout_ctx;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_dellink(%s)", vlan->ifname);

#ifdef CONFIG_VLAN_ASYNC
	if (vlan->removing)
		return;
#endif
	if (!vlan->configured) {
		// delete and free now!
		vlan_drop_and_free(vlan, hapd);
		return;
	}

	vlan->configured = 0;

	ifconfig_down(vlan->ifname);

#ifdef CONFIG_RSN_PREAUTH_COPY
	rsn_preauth_snoop_deinit(hapd, vlan->ifname, vlan->rsn_preauth);
#endif /* CONFIG_RSN_PREAUTH_COPY */

	vlan_deconfigure(vlan, hapd);
}


static void vlan_newlink(char *ifname, struct hostapd_data *hapd)
{
	struct hostapd_vlan *vlan;

	for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
		if (os_strcmp(ifname, vlan->ifname))
			continue;
		if (vlan->configured)
			break;

		eloop_cancel_timeout(vlan_newlink_cb, vlan, hapd);
		eloop_cancel_timeout(vlan_dellink_cb, vlan, hapd);
		eloop_register_timeout(0, 0,
				       vlan_newlink_cb, vlan, hapd);
		break;
	}
}


static void vlan_dellink(char *ifname, struct hostapd_data *hapd)
{
	struct hostapd_vlan *vlan = hapd->conf->vlan;

	for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
		if (os_strcmp(ifname, vlan->ifname))
			continue;
#ifdef CONFIG_VLAN_ASYNC
		if (vlan->removing)
			continue;
#endif /* CONFIG_VLAN_ASYNC */

		eloop_cancel_timeout(vlan_newlink_cb, vlan, hapd);
		eloop_cancel_timeout(vlan_dellink_cb, vlan, hapd);

		if (!vlan->configured)
			vlan_drop_and_free(vlan, hapd);
		else
			eloop_register_timeout(0, 0, vlan_dellink_cb, vlan,
					       hapd);
		break;
	}
}

static int vlan_handle_read_ifname(struct hostapd_iface *iface, void *ctx)
{
        struct vlan_handle_read_ifname_data *data = ctx;
        struct hostapd_data *hapd;
        size_t j;

        for (j = 0; j < iface->num_bss; j++) {
                hapd = iface->bss[j];
		if (data->del)
			vlan_dellink(data->ifname, hapd);
		else
			vlan_newlink(data->ifname, hapd);
        }

	return 0;
}


#ifndef CONFIG_VLAN_ASYNC
static void vlan_event_receive(void *ctx,struct ifinfomsg *ifi, u8 *buf, size_t len, int del)
{
        int attrlen;
        struct rtattr *attr;
        char ifname[IFNAMSIZ + 1];
	struct vlan_handle_read_ifname_data data;

        ifname[0] = '\0';

        attrlen = len;
        attr = (struct rtattr *) buf;
        while (RTA_OK(attr, attrlen)) {
                switch (attr->rta_type) {
                case IFLA_IFNAME:
                        if (RTA_PAYLOAD(attr) >= IFNAMSIZ)
                                break;
                        os_memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));
                        ifname[RTA_PAYLOAD(attr)] = '\0';
                        break;
                }
                attr = RTA_NEXT(attr, attrlen);
        }

        if (!ifname[0])
		return;
	if (del && vlan_if_nametoindex(ifname))
		return;

	data.del = del;
	os_strlcpy(data.ifname, ifname, sizeof(data.ifname));

	if (!full_dynamic_vlan ||
	    !full_dynamic_vlan->interfaces ||
	    !full_dynamic_vlan->interfaces->for_each_interface)
	    return;
	full_dynamic_vlan->interfaces->for_each_interface(
		    full_dynamic_vlan->interfaces,
		    vlan_handle_read_ifname,
		    &data);
}

static void vlan_event_receive_newlink(void *ctx,struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	vlan_event_receive(ctx, ifi, buf, len, 0);
}

static void vlan_event_receive_dellink(void *ctx,struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	vlan_event_receive(ctx, ifi, buf, len, 1);
}

#else /* CONFIG_VLAN_ASYNC */
static void
vlan_handle_wait_for_iface_hapd(struct hostapd_data *hapd,
				struct vlan_handle_read_ifname_data *data)
{
	struct hostapd_vlan *vlan;

	for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
		if (!vlan->wait_for_iface_cb)
			continue;
		if (os_strcmp(data->ifname, vlan->wait_for_iface))
			continue;
		if (BIT(vlan->waiting) & data->del)
			vlan->wait_for_iface_cb(vlan, hapd);
	}
}

static int vlan_handle_wait_for_iface(struct hostapd_iface *iface, void *ctx)
{
        struct vlan_handle_read_ifname_data *data = ctx;
        struct hostapd_data *hapd;
        size_t j;

        for (j = 0; j < iface->num_bss; j++) {
                hapd = iface->bss[j];
		vlan_handle_wait_for_iface_hapd(hapd, data);
        }

	return 0;
}


static void onlinkchange(struct nl_cache *cache, struct nl_object *obj, int action, void *arg)
{
	struct hapd_interfaces *interfaces = arg;
	struct vlan_handle_read_ifname_data data;
	struct rtnl_link *link;
	char *ifname;

	if (!interfaces || !interfaces->for_each_interface)
		return;

	if (os_strcmp(nl_object_get_type(obj),"route/link"))
		return; /* invalid type */

	link = (struct rtnl_link *) obj;
	ifname = rtnl_link_get_name(link);

        if (!ifname || !ifname[0])
		return;

	os_memset(&data, 0, sizeof(data));
	os_strlcpy(data.ifname, ifname, sizeof(data.ifname));

	if (action == 1 || (action == 2 && !vlan_if_nametoindex(ifname))) { /* NEWLINK or DELLINK */
		data.del = (action == 2); /* NL_ACT_DEL */

		interfaces->for_each_interface(
			    interfaces,
			    vlan_handle_read_ifname,
			    &data);
	}

	data.del = 0;
	if (action == 1)
		data.del |= BIT(VLAN_EVENT_NEWLINK);
	if (action == 2)
		data.del |= BIT(VLAN_EVENT_DELLINK);

	if (rtnl_link_get_flags(link) & IFF_UP)
		data.del |= BIT(VLAN_EVENT_IFF_UP);
	else
		data.del |= BIT(VLAN_EVENT_IFF_DOWN);
	
	if (rtnl_link_get_master(link))
		data.del |= BIT(VLAN_EVENT_SLAVE);
	else
		data.del |= BIT(VLAN_EVENT_MASTER);

	interfaces->for_each_interface(
		    interfaces,
		    vlan_handle_wait_for_iface,
		    &data);
}

static void linkmngrupdate(int fd, void *eloop_ctx, void *timeout_ctx)
{
	struct nl_cache_mngr *linkcachemngr = eloop_ctx;
	if (nl_cache_mngr_data_ready(linkcachemngr) < 0) {
		/* an error happened */
	}
}


static int vlan_exists(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	struct hostapd_vlan *curr;

	for (curr = hapd->conf->vlan; curr; curr = curr->next)
		if (curr == vlan)
			return 1;

	return 0;
}


static void vlan_finish(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	char ifname[IFNAMSIZ];
	int fd;
	struct hapd_interfaces *interfaces;

	os_strlcpy(ifname, vlan->ifname, sizeof(ifname));

	if (eloop_cancel_timeout(vlan_newlink_cb, vlan, hapd))
		vlan_newlink_cb(vlan, hapd);
	if (eloop_cancel_timeout(vlan_dellink_cb, vlan, hapd))
		vlan_dellink_cb(vlan, hapd);
	if (!vlan_exists(vlan, hapd))
		return;
	
	interfaces = hapd->iface->interfaces;
	fd = nl_cache_mngr_get_fd(interfaces->vlan_priv->linkcachemngr);
	vlan_finish_async(vlan, hapd);
	while (vlan_exists(vlan, hapd))	{
		wpa_printf(MSG_DEBUG, "vlan_finish for %s running", ifname);
		linkmngrupdate(fd, interfaces->vlan_priv->linkcachemngr, NULL);
		vlan_finish_async(vlan, hapd);
	}

	wpa_printf(MSG_DEBUG, "vlan_finish for %s completed", ifname);
}
#endif /* CONFIG_VLAN_ASYNC */

int vlan_global_init(struct hapd_interfaces *interfaces)
{
#ifndef CONFIG_VLAN_ASYNC
	struct netlink_config *cfg = 0;
#endif

	interfaces->vlan_priv = os_zalloc(sizeof(*interfaces->vlan_priv));
	if (interfaces->vlan_priv == NULL)
		goto err;

#ifndef CONFIG_VLAN_ASYNC
	full_dynamic_vlan = os_zalloc(sizeof(*full_dynamic_vlan));
	if (full_dynamic_vlan == NULL)
		goto err;

	full_dynamic_vlan->interfaces = interfaces;

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		goto err;

        cfg->ctx = NULL;
        cfg->newlink_cb = vlan_event_receive_newlink;
        cfg->dellink_cb = vlan_event_receive_dellink;
        full_dynamic_vlan->nl = netlink_init(cfg);
        if (full_dynamic_vlan->nl == NULL)
	{
		wpa_printf(MSG_ERROR, "VLAN: %s: netlink_init failed: %s",
			   __func__, strerror(errno));
		goto err;
	}

#else /* CONFIG_VLAN_ASYNC */
	if (nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &interfaces->vlan_priv->linkcachemngr) < 0) {
		goto err;
	}
	if (nl_cache_mngr_add(interfaces->vlan_priv->linkcachemngr, "route/link", &onlinkchange, interfaces, &interfaces->vlan_priv->linkcache) < 0) {
		goto err;
	}
	eloop_register_read_sock(nl_cache_mngr_get_fd(interfaces->vlan_priv->linkcachemngr), &linkmngrupdate, interfaces->vlan_priv->linkcachemngr, NULL);
#endif /* CONFIG_VLAN_ASYNC */

	return 0;
err:
#ifdef CONFIG_VLAN_ASYNC
	if (interfaces->vlan_priv->linkcachemngr) {
		eloop_unregister_read_sock(nl_cache_mngr_get_fd(interfaces->vlan_priv->linkcachemngr));
		nl_cache_mngr_free(interfaces->vlan_priv->linkcachemngr);
	}
#else /* CONFIG_VLAN_ASYNC */
	if (full_dynamic_vlan)
	{
		os_free(full_dynamic_vlan);
		full_dynamic_vlan = NULL;
	}
	if (cfg)
	{
		os_free(cfg);
		cfg = NULL;
	}
#endif /* CONFIG_VLAN_ASYNC */
	if (interfaces->vlan_priv) {
		os_free(interfaces->vlan_priv);
		interfaces->vlan_priv = NULL;
	}

	return -1;
}


void vlan_global_deinit(struct hapd_interfaces *interfaces)
{
#ifdef CONFIG_VLAN_ASYNC
	if (interfaces && interfaces->vlan_priv && interfaces->vlan_priv->linkcachemngr) {
		eloop_unregister_read_sock(nl_cache_mngr_get_fd(interfaces->vlan_priv->linkcachemngr));
		nl_cache_mngr_free(interfaces->vlan_priv->linkcachemngr);
	}
#endif /* CONFIG_VLAN_ASYNC */
	if (interfaces && interfaces->vlan_priv) {
		os_free(interfaces->vlan_priv);
		interfaces->vlan_priv = NULL;
	}
#ifndef CONFIG_VLAN_ASYNC
	if (full_dynamic_vlan == NULL)
		return;
	netlink_deinit(full_dynamic_vlan->nl);
	os_free(full_dynamic_vlan);
	full_dynamic_vlan = NULL;
#endif /* CONFIG_VLAN_ASYNC */
}

#endif /* CONFIG_FULL_DYNAMIC_VLAN */


static int vlan_dynamic_add(struct hostapd_data *hapd,
			    struct hostapd_vlan *vlan)
{
	while (vlan) {
		if (vlan->vlan_id != VLAN_ID_WILDCARD) {
			if (vlan_if_add(hapd, vlan, 1)) {
				wpa_printf(MSG_ERROR, "VLAN: Could not add "
					   "VLAN %s: %s", vlan->ifname,
					   strerror(errno));
				return -1;
			}
#ifdef CONFIG_FULL_DYNAMIC_VLAN
			vlan_newlink(vlan->ifname, hapd);
#endif /* CONFIG_FULL_DYNAMIC_VLAN */
		}

		vlan = vlan->next;
	}

	return 0;
}


static void vlan_dynamic_remove(struct hostapd_data *hapd,
				struct hostapd_vlan *vlan)
{
	struct hostapd_vlan *next;

	wpa_printf(MSG_DEBUG, "VLAN: %s: running %s",
		   hapd->conf->iface, __func__);

	while (vlan) {
		next = vlan->next;

#ifndef CONFIG_FULL_DYNAMIC_VLAN
		if (vlan->vlan_id != VLAN_ID_WILDCARD &&
		    vlan_if_remove(hapd, vlan)) {
			wpa_printf(MSG_ERROR, "VLAN: Could not remove VLAN "
				   "iface: %s: %s",
				   vlan->ifname, strerror(errno));
		}
#else
		if (vlan->vlan_id != VLAN_ID_WILDCARD) {
			vlan_dellink(vlan->ifname, hapd);
#ifdef CONFIG_VLAN_ASYNC
			vlan_finish(vlan, hapd);
#endif
		}
#endif /* CONFIG_FULL_DYNAMIC_VLAN */

		vlan = next;
	}

	wpa_printf(MSG_DEBUG, "VLAN: %s: done running %s",
		   hapd->conf->iface, __func__);
}


int vlan_init(struct hostapd_data *hapd)
{
#ifdef CONFIG_FULL_DYNAMIC_VLAN
#ifndef CONFIG_VLAN_NETLINK
#ifndef CONFIG_VLAN_ASYNC
	vlan_set_name_type(hapd->conf->ssid.vlan_naming ==
			   DYNAMIC_VLAN_NAMING_WITH_DEVICE ?
			   VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD :
			   VLAN_NAME_TYPE_PLUS_VID_NO_PAD);
#endif /* CONFIG_VLAN_ASYNC */
#endif /* CONFIG_VLAN_NETLINK */
#endif /* CONFIG_FULL_DYNAMIC_VLAN */

	if ((hapd->conf->ssid.dynamic_vlan != DYNAMIC_VLAN_DISABLED ||
	     hapd->conf->ssid.per_sta_vif) && !hapd->conf->vlan) {
		/* dynamic vlans enabled but no (or empty) vlan_file given */
		struct hostapd_vlan *vlan;
		vlan = os_zalloc(sizeof(*vlan));
		if (vlan == NULL) {
			wpa_printf(MSG_ERROR, "Out of memory while assigning "
				   "VLAN interfaces");
			return -1;
		}

		vlan->vlan_id = VLAN_ID_WILDCARD;
		os_snprintf(vlan->ifname, sizeof(vlan->ifname), "%s.#",
			    hapd->conf->iface);
		vlan->next = hapd->conf->vlan;
		hapd->conf->vlan = vlan;
	}

	if (vlan_dynamic_add(hapd, hapd->conf->vlan))
		return -1;

        return 0;
}


void vlan_deinit(struct hostapd_data *hapd)
{
	struct hostapd_vlan *vlan;
	vlan_dynamic_remove(hapd, hapd->conf->vlan);

	vlan = hapd->conf->vlan;
	while (vlan) {
		wpa_printf(MSG_DEBUG, "VLAN: %s left over %s", hapd->conf->iface, vlan->ifname);
		vlan = vlan->next;
	}
}


struct hostapd_vlan * vlan_add_dynamic(struct hostapd_data *hapd,
				       struct hostapd_vlan *vlan,
				       int vlan_id,
				       struct vlan_description vlan_desc)
{
	struct hostapd_vlan *n = NULL;
	char ifname[IFNAMSIZ+1], *pos;

	if (vlan == NULL || vlan->vlan_id != VLAN_ID_WILDCARD)
		return NULL;

	wpa_printf(MSG_DEBUG, "VLAN: %s(vlan_id=%d ifname=%s)",
		   __func__, vlan_id, vlan->ifname);
	os_strlcpy(ifname, vlan->ifname, sizeof(ifname));
	pos = os_strchr(ifname, '#');
	if (pos == NULL)
		goto out;
	*pos++ = '\0';

	n = os_zalloc(sizeof(*n));
	if (n == NULL)
		goto out;

	n->vlan_id = vlan_id;
	n->vlan_desc = vlan_desc;
	n->dynamic_vlan = 1;
	n->dynamic_vlan_ref = 1;

	os_snprintf(n->ifname, sizeof(n->ifname), "%s%d%s", ifname, vlan_id,
		    pos);

	n->next = hapd->conf->vlan;
	hapd->conf->vlan = n;

out:
	return n;
}


void vlan_get_dynamic(struct hostapd_data *hapd, struct hostapd_vlan *vlan)
{
	vlan->dynamic_vlan_ref++;

	wpa_printf(MSG_DEBUG, "VLAN: %s(ifname=%s vlan_id=%d) ref <- %d",
		   __func__, hapd->conf->iface, vlan->vlan_id, vlan->dynamic_vlan_ref);
#ifdef CONFIG_VLAN_ASYNC
	if (vlan->removing)
		vlan_newlink_cb(vlan, hapd);
#endif /* CONFIG_VLAN_ASYNC */
}


int vlan_setup_dynamic(struct hostapd_data *hapd, struct hostapd_vlan *vlan)
{
	int ret;

	if (vlan->setup)
		return 0;

	ret = vlan_if_add(hapd, vlan, 0);
	vlan->setup = 1;

	return ret;
}


int vlan_remove_dynamic(struct hostapd_data *hapd, int vlan_id)
{
	struct hostapd_vlan *vlan;

	if (vlan_id <= 0)
		return 1;

	wpa_printf(MSG_DEBUG, "VLAN: %s(ifname=%s vlan_id=%d)",
		   __func__, hapd->conf->iface, vlan_id);

	vlan = hapd->conf->vlan;
	while (vlan) {
		if (vlan->vlan_id == vlan_id && vlan->dynamic_vlan) {
			vlan->dynamic_vlan_ref--;
			break;
		}
		vlan = vlan->next;
	}

	if (vlan == NULL)
		return 1;

	wpa_printf(MSG_DEBUG, "VLAN: %s(ifname=%s vlan_id=%d) ref <- %d",
		   __func__, hapd->conf->iface, vlan_id, vlan->dynamic_vlan_ref);
	if (vlan->dynamic_vlan_ref == 0)
		vlan_dellink(vlan->ifname, hapd);

	return 0;
}
