
#include "utils/includes.h"
#include "ifconfig.h"

#include "utils/common.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ap_drv_ops.h"

#include "utils/eloop.h"
#include "vlan_iface.h"
#include "vlan_priv.h"

#include "netlink/msg.h"
#include "netlink/cache.h"
#include "netlink/route/link.h"
#include "netlink/route/link/vlan.h"
#if 0
#include "netlink/route/link/bridge.h"
#endif
#include <assert.h>

static void vlan_configure_desetup(struct hostapd_vlan *vlan, struct hostapd_data *hapd);
static void wait_for_iface_cb(void *eloop_ctx, void *timeout_ctx);


static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	struct hostapd_vlan *vlan = arg;
	struct hostapd_data *hapd = vlan->hapd;

	wpa_printf(MSG_ERROR, "VLAN: %s error_handler got %d", vlan->ifname, err->error);

	if (vlan->wait_for_iface[0]) {
		eloop_cancel_timeout(&wait_for_iface_cb, vlan, hapd);
		eloop_register_timeout(0, 0, &wait_for_iface_cb, vlan, hapd);
	}
	return NL_SKIP;
}

static void vlan_bridge_name(char *br_name, struct hostapd_data *hapd, int vid)
{
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;

	if (hapd->conf->vlan_bridge[0]) {
		os_snprintf(br_name, IFNAMSIZ, "%s%d",
			    hapd->conf->vlan_bridge,  vid);
	} else if (tagged_interface) {
		os_snprintf(br_name, IFNAMSIZ, "br%s.%d",
			    tagged_interface, vid);
	} else {
		os_snprintf(br_name, IFNAMSIZ,
		            "brvlan%d", vid);
	}
}


static int state_wait_for_iface(struct hostapd_vlan *vlan,
			        struct hostapd_data *hapd)
{
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;

	interfaces = hapd->iface->interfaces;
	cache = interfaces->vlan_priv->linkcache;
	if (rtnl_link_name2i(cache, vlan->ifname))
		return 0;

	os_strlcpy(vlan->wait_for_iface, vlan->ifname,
		   sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_NEWLINK;
	wpa_printf(MSG_DEBUG, "VLAN: %s wait for interface to appear in cache", vlan->ifname);

	return 1;
}


/*
 * @returns 1 if msg has been sent and waiting for iface, 0 else
 */
static int state_set_iface_up(struct hostapd_vlan *vlan,
			      struct hostapd_data *hapd,
			      struct rtnl_link *link)
{
	int err, ret = 0;
	struct rtnl_link *change = NULL;
        struct nl_msg *msg = NULL;
	char *ifname = rtnl_link_get_name(link);

	if (rtnl_link_get_flags(link) & IFF_UP) {
		wpa_printf(MSG_DEBUG, "VLAN: %s %s is already UP",
			   vlan->ifname, ifname);
		return 0;
	}

	change = rtnl_link_alloc();
	if (!change) {
		wpa_printf(MSG_ERROR, "VLAN: failed to allocate new link");
		goto out;
	}

	rtnl_link_set_flags(change, IFF_UP);

	err = rtnl_link_build_change_request(link, change, 0, &msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to up %s msg: %s",
			   ifname, nl_geterror(err));
		goto out;
	}

	err = nl_send_auto(vlan->sk, msg);
	nlmsg_free(msg); msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to send up %s msg: %s",
			   ifname, nl_geterror(err));
		goto out;
	}

	ret = 1;
	os_strlcpy(vlan->wait_for_iface, ifname,
		   sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_IFF_UP;
	wpa_printf(MSG_DEBUG, "VLAN: %s ifconfig_up %s", vlan->ifname, ifname);

out:
	if (change)
		rtnl_link_put(change);

	return ret;
}


/* @param type
 *  type = 0 -> bridge
 *  type = 1 -> vlan on AP_VLAN
 *  type = 2 -> vlan on tagged interface
 * @returns 1 if msg has been sent and waiting for iface, 0 else
 */
static int state_create_iface(struct hostapd_vlan *vlan,
			      struct hostapd_data *hapd,
			      int type)
{
	int vid, err, flags, ifidx, ret = 0;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char if_name[IFNAMSIZ];
	char *iftype;
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	struct rtnl_link *link = NULL;
        struct nl_msg *msg = NULL;
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;

	interfaces = hapd->iface->interfaces;
	cache = interfaces->vlan_priv->linkcache;

	if (vlan->substate == 0)
		vid = vlan->vlan_desc.untagged;
	else
		vid = vlan->vlan_desc.tagged[vlan->substate - 1];

	if (!vid)
		return 0;

	switch (type) {
	case 0: /* bridge */
		vlan_bridge_name(if_name, hapd, vid);
		flags = DVLAN_CLEAN_BR;
		iftype = "bridge";
		ifidx = 0;
		break;
	case 1:
		if (vlan->substate == 0)
			return 0; /* untagged vlan does not need this on WiFi side */

		os_snprintf(if_name, sizeof(if_name), "%s.%d", vlan->ifname,
			    vid);
		flags = DVLAN_CLEAN_VLAN;
		iftype = "vlan";
		ifidx = rtnl_link_name2i(cache, vlan->ifname);
		if (!ifidx)
			return 0; /* ups, impossible */
		break;
	case 2:
		if (!tagged_interface)
			return 0;

		if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    tagged_interface, vid);
		else
			os_snprintf(if_name, sizeof(if_name), "vlan%d", vid);
		flags = DVLAN_CLEAN_VLAN;
		iftype = "vlan";
		ifidx = rtnl_link_name2i(cache, tagged_interface);
		if (!ifidx)
			return 0; /* ups, impossible */
		break;
	default:
		/* err */
		return 0;
	}

	link = rtnl_link_get_by_name(cache, if_name);

	if (link) {
		wpa_printf(MSG_DEBUG, "VLAN: %s %s already exists",
			   vlan->ifname, if_name);
		dyn_iface_get(if_name, "", 0, hapd);
		ret = state_set_iface_up(vlan, hapd, link);
		goto out;
	}

	dyn_iface_get(if_name, "", flags, hapd);
	
	link = rtnl_link_alloc();
	if (!link) {
		wpa_printf(MSG_ERROR, "VLAN: failed to allocate new link");
		goto out;
	}

	err = rtnl_link_set_type(link, iftype);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to set type %s: %s",
			   iftype, nl_geterror(err));
		goto out;
	}

	rtnl_link_set_name(link, if_name);
	rtnl_link_set_flags(link, IFF_UP);

	/* VLAN: set VID and parent iface */
	switch (type) {
	case 0:
		break;
	case 1:
	case 2:
		rtnl_link_set_link(link, ifidx);
		err = rtnl_link_vlan_set_id(link, vid);
		if (err < 0) {
			wpa_printf(MSG_ERROR, "VLAN: failed to set link vlan id: %s",
				   nl_geterror(err));
			goto out;
		}
		break;
	}

 	err = rtnl_link_build_add_request(link, NLM_F_CREATE, &msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to create %s msg: %s",
			   if_name, nl_geterror(err));
		goto out;
	}

	err = nl_send_auto(vlan->sk, msg);
	nlmsg_free(msg); msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to send create %s msg: %s",
			   if_name, nl_geterror(err));
		goto out;
	}

	ret = 1;

	os_strlcpy(vlan->wait_for_iface, if_name, sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_NEWLINK;
	wpa_printf(MSG_DEBUG, "VLAN: %s create %s", vlan->ifname, if_name);

out:
	if (link)
		rtnl_link_put(link);

	return ret;
}

/* @param type
 *  type = 0 -> bridge for AP_VLAN
 *  type = 1 -> bridge for tagged interface
 * @returns 1 if msg has been sent and waiting for ack, 0 else
 */
static int state_add_to_bridge(struct hostapd_vlan *vlan,
			       struct hostapd_data *hapd,
			       int type)
{
	int vid, err, flags, br_ifidx, ifidx, ret = 0;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char if_name[IFNAMSIZ], if_bridge[IFNAMSIZ];
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	struct rtnl_link *link = NULL, *bridge = NULL, *change = NULL;
        struct nl_msg *msg = NULL;
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;

	interfaces = hapd->iface->interfaces;
	cache = interfaces->vlan_priv->linkcache;

	if (vlan->substate == 0)
		vid = vlan->vlan_desc.untagged;
	else
		vid = vlan->vlan_desc.tagged[vlan->substate - 1];

	/* get iface name */
	switch (type) {
	case 0: /* AP_VLAN */
		if (vlan->substate == 0)
			os_strlcpy(if_name, vlan->ifname, sizeof(if_name));
		else if (!vid)
			return 0;
		else
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    vlan->ifname, vid);
		flags = DVLAN_CLEAN_WLAN_PORT;
		break;
	case 1:
		if (!vid)
			return 0;

		if (!tagged_interface)
			return 0;

		if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    tagged_interface, vid);
		else
			os_snprintf(if_name, sizeof(if_name), "vlan%d", vid);

		flags = DVLAN_CLEAN_VLAN_PORT;
		break;
	default:
		return 0;
	}

	/* get bridge name */
	switch (type) {
	case 0: /* AP_VLAN to bridge */
		if (!vlan->vlan_desc.notempty && !vlan->substate &&
		    hapd->conf->bridge[0])
 			/* untagged = zero */
			os_strlcpy(if_bridge, hapd->conf->bridge, sizeof(if_bridge));
		else if (!vid)
			return 0;
		else /* vlan given */
			vlan_bridge_name(if_bridge, hapd, vid);
		break;
	case 1: /* tagged iface */
		if (!vid)
			return 0;
		else /* vlan given */
			vlan_bridge_name(if_bridge, hapd, vid);
		break;
	}

	/* add if_name to bridge */
	bridge = rtnl_link_get_by_name(cache, if_bridge);
	link = rtnl_link_get_by_name(cache, if_name);
	if (!link || !bridge) {
		wpa_printf(MSG_ERROR, "VLAN: bridge or link not found %s/%s, %p/%p", if_bridge, if_name, bridge, link);
		goto out;
	}
#if 0
	if (!rtnl_link_is_bridge(bridge)) {
		wpa_printf(MSG_ERROR, "VLAN: bridge %s is not a bridge", if_bridge);
		goto out;
	}
#endif
	br_ifidx = rtnl_link_get_ifindex(bridge);
	ifidx = rtnl_link_get_master(link);
	if (ifidx != 0 && ifidx != br_ifidx) {
		wpa_printf(MSG_ERROR, "VLAN: link %s already on different bridge %d", if_name, ifidx);
		goto out;
	}

	if (ifidx != 0) { /* already exists */
		wpa_printf(MSG_DEBUG, "VLAN: %s %s already in %s",
			   vlan->ifname, if_name, if_bridge);
		dyn_iface_get(if_bridge, if_name, 0, hapd);
		goto out; /* not a real error but nl_link_put needed */
	} else
		dyn_iface_get(if_bridge, if_name, flags, hapd);
		
	change = rtnl_link_alloc();
	if (!change) {
		wpa_printf(MSG_ERROR, "VLAN: could not alloc change link object");
		goto out;
	}
	
	rtnl_link_set_master(change, br_ifidx);
	err = rtnl_link_build_change_request(link, change, 0, &msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to create addif msg: %s",
			   nl_geterror(err));
		goto out;
	}

	err = nl_send_auto(vlan->sk, msg);
	nlmsg_free(msg); msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to send addif msg: %s",
			   nl_geterror(err));
		goto out;
	}

	ret = 1;
	os_strlcpy(vlan->wait_for_iface, if_name, sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_SLAVE;
	wpa_printf(MSG_DEBUG, "VLAN: %s add %s to %s", vlan->ifname, if_name, if_bridge);

out:
	if (bridge)
		rtnl_link_put(bridge);
	if (link)
		rtnl_link_put(link);
	if (change)
		rtnl_link_put(change);

	return ret;
}


/* @param type
 *  type = 0 -> bridge
 *  type = 1 -> vlan on AP_VLAN
 *  type = 2 -> vlan on tagged interface
 * @returns 1 if msg has been sent and waiting for iface, 0 else
 */
static int state_set_iface_down(struct hostapd_vlan *vlan,
			        struct hostapd_data *hapd,
			        int type)
{
	int vid, err, flags, ret = 0;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char if_name[IFNAMSIZ];
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	struct rtnl_link *link = NULL, *change = NULL;
        struct nl_msg *msg = NULL;
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;

	interfaces = hapd->iface->interfaces;
	cache = interfaces->vlan_priv->linkcache;

	if (vlan->substate == 0)
		vid = vlan->vlan_desc.untagged;
	else
		vid = vlan->vlan_desc.tagged[vlan->substate - 1];

	if (!vid)
		return 0;

	switch (type) {
	case 0: /* bridge */
		vlan_bridge_name(if_name, hapd, vid);
		flags = DVLAN_CLEAN_BR;
		break;
	case 1: 
		if (vlan->substate == 0)
			return 0;
		os_snprintf(if_name, sizeof(if_name), "%s.%d",
			    vlan->ifname, vid);
		flags = DVLAN_CLEAN_VLAN;
		break;
	case 2:
		if (!tagged_interface)
			return 0;

		if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    tagged_interface, vid);
		else
			os_snprintf(if_name, sizeof(if_name), "vlan%d", vid);
		flags = DVLAN_CLEAN_VLAN;
		break;
	default:
		/* err */
		return 0;
	}

	flags = dyn_iface_put(if_name, "", hapd) & flags;
	if (!flags)
		return -1; /* skip interface deletion */

	link = rtnl_link_get_by_name(cache, if_name);
	if (!link)
		wpa_printf(MSG_ERROR, "VLAN: link %s not found for iff_down", if_name);

	if (!link)
		return 0;

	if (!(rtnl_link_get_flags(link) & IFF_UP))
		goto out;

	change = rtnl_link_alloc();
	if (!change) {
		wpa_printf(MSG_ERROR, "VLAN: failed to allocate new link");
		goto out;
	}

	rtnl_link_unset_flags(change, IFF_UP);

	err = rtnl_link_build_change_request(link, change, 0, &msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to down %s msg: %s",
			   if_name, nl_geterror(err));
		goto out;
	}

	err = nl_send_auto(vlan->sk, msg);
	nlmsg_free(msg); msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to send create %s msg: %s",
			   if_name, nl_geterror(err));
		goto out;
	}

	ret = 1;
	os_strlcpy(vlan->wait_for_iface, if_name, sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_IFF_DOWN;
	wpa_printf(MSG_DEBUG, "VLAN: %s ifconfig_down %s", vlan->ifname, if_name);

out:
	if (link)
		rtnl_link_put(link);
	if (change)
		rtnl_link_put(change);

	return ret;
}


/* @param type
 *  type = 0 -> bridge
 *  type = 1 -> vlan on AP_VLAN
 *  type = 2 -> vlan on tagged interface
 * @returns 1 if msg has been sent and waiting for iface, 0 else
 */
static int state_delete_iface(struct hostapd_vlan *vlan,
			      struct hostapd_data *hapd,
			      int type)
{
	int vid, err, ret = 0;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char if_name[IFNAMSIZ];
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	struct rtnl_link *link = NULL;
        struct nl_msg *msg = NULL;
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;
	struct nl_sock *sk = NULL;

	interfaces = hapd->iface->interfaces;
	cache = interfaces->vlan_priv->linkcache;

	if (vlan->substate == 0)
		vid = vlan->vlan_desc.untagged;
	else
		vid = vlan->vlan_desc.tagged[vlan->substate - 1];

	if (!vid)
		return 0;

	switch (type) {
	case 0: /* bridge */
		vlan_bridge_name(if_name, hapd, vid);
		break;
	case 1:
		if (vlan->substate == 0)
			return 0; /* untagged vlan does not need this on WiFi side */

		os_snprintf(if_name, sizeof(if_name), "%s.%d", vlan->ifname,
			    vid);
		break;
	case 2:
		if (!tagged_interface)
			return 0;

		if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    tagged_interface, vid);
		else
			os_snprintf(if_name, sizeof(if_name), "vlan%d", vid);
		break;
	default:
		/* err */
		return 0;
	}

	link = rtnl_link_get_by_name(cache, if_name);
	if (!link) {
		wpa_printf(MSG_WARNING, "VLAN: lookup link %s directly from kernel", if_name);

		sk = nl_socket_alloc();
		if (!sk) {
			wpa_printf(MSG_ERROR, "VLAN: vlan:async:failed to init netlink socket");
			goto out;
		}

		err = nl_connect(sk, NETLINK_ROUTE);
		if (err < 0) {
			wpa_printf(MSG_ERROR, "VLAN: vlan:async:failed to connect to netlink; %s", nl_geterror(err));
			goto out;
		}

		err = rtnl_link_get_kernel(sk, 0, if_name, &link);
		if (err < 0) {
			wpa_printf(MSG_ERROR, "VLAN: link %s not found for deletion: %s", if_name, nl_geterror(err));
			goto out;
		}
	}

	if (!link) {
		wpa_printf(MSG_ERROR, "VLAN: link %s not found for deletion", if_name);
		goto out;
	}

 	err = rtnl_link_build_delete_request(link, &msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to create delete for %s"
			   " msg: %s", if_name, nl_geterror(err));
		goto out;
	}

	err = nl_send_auto(vlan->sk, msg);
	nlmsg_free(msg); msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to send delete for %s"
			   " msg: %s", if_name, nl_geterror(err));
		goto out;
	}

	wpa_printf(MSG_DEBUG, "VLAN: %s delete %s", vlan->ifname, if_name);
	os_strlcpy(vlan->wait_for_iface, if_name, sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_DELLINK;
	ret = 1;

out:
	if (link)
		rtnl_link_put(link);
	if (sk)
		nl_socket_free(sk);

	return ret;
}


/* @param type
 *  type = 0 -> bridge for AP_VLAN
 *  type = 1 -> bridge for tagged interface
 * @returns 1 if msg has been sent and waiting for ack, 0 else
 */
static int state_remove_from_bridge(struct hostapd_vlan *vlan,
				    struct hostapd_data *hapd,
				    int type)
{
	int vid, err, flags, br_ifidx, ifidx, ret = 0;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char if_name[IFNAMSIZ], if_bridge[IFNAMSIZ];
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	struct rtnl_link *link = NULL, *bridge = NULL, *change = NULL;
        struct nl_msg *msg = NULL;
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;

	interfaces = hapd->iface->interfaces;
	cache = interfaces->vlan_priv->linkcache;

	if (vlan->substate == 0)
		vid = vlan->vlan_desc.untagged;
	else
		vid = vlan->vlan_desc.tagged[vlan->substate - 1];

	/* get iface name */
	switch (type) {
	case 0: /* AP_VLAN */
		if (vlan->substate == 0)
			os_strlcpy(if_name, vlan->ifname, sizeof(if_name));
		else if (!vid)
			return 0;
		else
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    vlan->ifname, vid);
		flags = DVLAN_CLEAN_WLAN_PORT;
		break;
	case 1:
		if (!vid)
			return 0;

		if (!tagged_interface)
			return 0;

		if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
			os_snprintf(if_name, sizeof(if_name), "%s.%d",
				    tagged_interface, vid);
		else
			os_snprintf(if_name, sizeof(if_name), "vlan%d", vid);

		flags = DVLAN_CLEAN_VLAN_PORT;
		break;
	default:
		return 0;
	}

	/* get bridge name */
	switch (type) {
	case 0: /* AP_VLAN to bridge */
		if (!vlan->vlan_desc.notempty && !vlan->substate &&
		    hapd->conf->bridge[0])
 			/* untagged = zero */
			os_strlcpy(if_bridge, hapd->conf->bridge, sizeof(if_bridge));
		else if (!vid)
			return 0;
		else /* vlan given */
			vlan_bridge_name(if_bridge, hapd, vid);
		break;
	case 1: /* tagged iface */
		if (!vid)
			return 0;
		else /* vlan given */
			vlan_bridge_name(if_bridge, hapd, vid);
		break;
	}

	/* remove if_name to bridge */
	flags = dyn_iface_put(if_bridge, if_name, hapd) & flags;

	if (!flags)
		goto out;

	bridge = rtnl_link_get_by_name(cache, if_bridge);
	link = rtnl_link_get_by_name(cache, if_name);
	if (!link) {
		wpa_printf(MSG_ERROR, "VLAN: bridge or link not found %s/%s, %p/%p during removal", if_bridge, if_name, bridge, link);
		goto out;
	}
	if (!bridge) {
		wpa_printf(MSG_ERROR, "VLAN: bridge or link not found %s/%s, %p/%p during removal", if_bridge, if_name, bridge, link);
		br_ifidx = 0;
	} else {
#if 0
		if (!rtnl_link_is_bridge(bridge)) {
			wpa_printf(MSG_ERROR, "VLAN: bridge %s is not a bridge", if_bridge);
			goto out;
		}
#endif
		br_ifidx = rtnl_link_get_ifindex(bridge);
	}
	ifidx = rtnl_link_get_master(link);

	if (ifidx && br_ifidx && ifidx != br_ifidx)
		wpa_printf(MSG_ERROR, "VLAN: link %s already on different bridge %d", if_name, ifidx);
	else if (ifidx == 0) { /* already exists */
		wpa_printf(MSG_ERROR, "VLAN: link %s not in bridge %s", if_name, if_bridge);
		goto out;
	}

	change = rtnl_link_alloc();
	if (!change) {
		wpa_printf(MSG_ERROR, "VLAN: could not alloc change link object");
		goto out;
	}
	
	rtnl_link_set_master(change, 0);
	err = rtnl_link_build_change_request(link, change, 0, &msg);
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to create addif msg: %s",
			   nl_geterror(err));
		goto out;
	}

	err = nl_send_auto(vlan->sk, msg);
	nlmsg_free(msg); msg = NULL;
	if (err < 0) {
		wpa_printf(MSG_ERROR, "VLAN: failed to send addif msg: %s",
			   nl_geterror(err));
		goto out;
	}

	wpa_printf(MSG_DEBUG, "VLAN: %s remove %s from %s", vlan->ifname, if_name, if_bridge);

	ret = 1;
	os_strlcpy(vlan->wait_for_iface, if_name, sizeof(vlan->wait_for_iface));
	vlan->waiting = VLAN_EVENT_MASTER;

out:
	if (bridge)
		rtnl_link_put(bridge);
	if (link)
		rtnl_link_put(link);

	return ret;
}


void vlan_configure_run(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	int arg;

	if (!vlan->skipStep)
		vlan->substate++;
	else
		vlan->skipStep = 0;

	wpa_printf(MSG_DEBUG, "VLAN: %s configure entering state %d.%d", vlan->ifname, vlan->state, vlan->substate);

	while (vlan->state == 0) {
		/* AP_VLAN iface was created */
		if (state_wait_for_iface(vlan, hapd))
			break;
		vlan->state++;
		vlan->substate = 0;
	}

	while (vlan->state == 1 || /* 1: create all bridge interfaces */
	       vlan->state == 2 || /* 2: create all AP_VLAN/802.1q ifaces */
	       vlan->state == 3) { /* 3: create all tagged 802.1q ifaces */
		arg = vlan->state - 1;
		while (vlan->substate <= MAX_NUM_TAGGED_VLAN) {
			if (state_create_iface(vlan, hapd, arg))
				break;
			else
				vlan->substate++;
		}
		if (vlan->substate <= MAX_NUM_TAGGED_VLAN)
			break;
		vlan->state++;
		vlan->substate = 0;
	}

	while (vlan->state == 4 || /* add AP_VLAN interfaces to bridges */
	       vlan->state == 5) { /* add tagged interfaces to bridges */
		arg = vlan->state - 4;
		while (vlan->substate <= MAX_NUM_TAGGED_VLAN) {
			if (state_add_to_bridge(vlan, hapd, arg))
				break;
			vlan->substate++;
		}
		if (vlan->substate <= MAX_NUM_TAGGED_VLAN)
			break;
		vlan->state++;
		vlan->substate = 0;
	}

	while (vlan->state == 6) { /* done */
		vlan_configure_desetup(vlan, hapd);
		vlan->wait_for_iface[0] = '\0';
		vlan->wait_for_iface_cb = NULL;
		break;
	}

	wpa_printf(MSG_DEBUG, "VLAN: %s configure reached state %d.%d", vlan->ifname, vlan->state, vlan->substate);

}


void vlan_deconfigure_run(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	struct hapd_interfaces *interfaces;
	struct nl_cache *cache = NULL;
	struct hostapd_vlan *first, *prev, *curr;
	int arg;

	if (!vlan->skipStep) {
		if (vlan->state == 1 || vlan->state == 2 || vlan->state == 3)
			vlan->subsubstate++;
		else
			vlan->substate--;
	} else
		vlan->skipStep = 0;

	wpa_printf(MSG_DEBUG, "VLAN: %s deconfigure entering state %d.%d.%d", vlan->ifname, vlan->state, vlan->substate, vlan->subsubstate);

	while (vlan->state == 6) { /* done */
		vlan->state--;
		vlan->substate = MAX_NUM_TAGGED_VLAN;
	}

	while (vlan->state == 4 || /* del AP_VLAN interfaces to bridges */
	       vlan->state == 5) { /* del tagged interfaces to bridges */
		arg = vlan->state - 4;
		while (vlan->substate >= 0) {
			if (state_remove_from_bridge(vlan, hapd, arg))
				break;
			vlan->substate--;
		}
		if (vlan->substate >= 0)
			break;
		vlan->state--;
		vlan->substate = MAX_NUM_TAGGED_VLAN;
		vlan->subsubstate = 0;
	}

	while (vlan->state == 1 || /* 1: delete all bridge interfaces */
	       vlan->state == 2 || /* 2: delete all AP_VLAN/802.1q ifaces */
	       vlan->state == 3) { /* 3: delete all tagged 802.1q ifaces */
		arg = vlan->state - 1;
		while (vlan->substate >= 0) {
			if (vlan->subsubstate == 0) {
				switch (state_set_iface_down(vlan, hapd, arg))
				{
					case -1:
						vlan->subsubstate++;
					case 0:
						vlan->subsubstate++;
					case 1:
						break;
				}
			}
			if (vlan->subsubstate == 0)
				break;
			if (vlan->subsubstate == 1) {
				if (state_delete_iface(vlan, hapd, arg))
					break;
				else
					vlan->subsubstate++;
			}
			vlan->subsubstate = 0;
			vlan->substate--;
		}
		if (vlan->substate >= 0)
			break;
		vlan->state--;
		vlan->substate = MAX_NUM_TAGGED_VLAN;
		vlan->subsubstate = 0;
	}

	while (vlan->state == 0) { /* remove vlan interface itself */
		interfaces = hapd->iface->interfaces;
		cache = interfaces->vlan_priv->linkcache;

		if (rtnl_link_name2i(cache, vlan->ifname)) {
			wpa_printf(MSG_DEBUG, "VLAN: %s delete %s", vlan->ifname, vlan->ifname);
			if (vlan_if_remove(hapd, vlan))
				wpa_printf(MSG_ERROR, "VLAN: Could not remove VLAN "
					   "iface: %s: %s",
					   vlan->ifname, strerror(errno));
		}

		vlan_configure_desetup(vlan, hapd);

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
		if (!curr) {
			wpa_printf(MSG_ERROR, "VLAN: %s ptr %p not found", vlan->ifname, vlan);
		} else {
			wpa_printf(MSG_ERROR, "VLAN: %s ptr %p freed", vlan->ifname, vlan);
		}

		break;
	}
}



static void wait_for_iface_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_vlan *vlan = eloop_ctx;
	struct hostapd_data *hapd = timeout_ctx;

	vlan->wait_for_iface[0] = '\0';
	if (vlan->removing) {
		vlan_deconfigure_run(vlan, hapd);
	} else {
		vlan_configure_run(vlan, hapd);
	}
}


static void wait_for_iface(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	/* defer processing since cache needs to finish its newlink processing first so iface shows up in cache */
	eloop_cancel_timeout(&wait_for_iface_cb, vlan, hapd);
	eloop_register_timeout(0, 0, &wait_for_iface_cb, vlan, hapd);
}


static void vlan_configure_netlink_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct hostapd_vlan *vlan = eloop_ctx;

	nl_recvmsgs(vlan->sk, vlan->cb);
}


static void vlan_configure_desetup(struct hostapd_vlan *vlan,
				   struct hostapd_data *hapd)
{
	int fd;

	eloop_cancel_timeout(&wait_for_iface_cb, vlan, hapd);

	if (vlan->sk) {
		fd = nl_socket_get_fd(vlan->sk);
		eloop_unregister_read_sock(fd);
		nl_socket_free(vlan->sk);
	}
	vlan->sk = NULL;
	if (vlan->cb)
		nl_cb_put(vlan->cb);
	vlan->cb = NULL;
}


static void vlan_configure_setup(struct hostapd_vlan *vlan,
				 struct hostapd_data *hapd)
{
	int fd;

	vlan->hapd = hapd;

	if (vlan->sk)
		return;

	vlan->sk = nl_socket_alloc();
	if (!vlan->sk) {
		wpa_printf(MSG_ERROR, "VLAN: vlan:async:failed to init netlink socket");
		return;
	}

	if (nl_connect(vlan->sk, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: vlan:async:failed to connect to netlink");
		return;
	}

	fd = nl_socket_get_fd(vlan->sk);
	vlan->cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!vlan->cb) {
		wpa_printf(MSG_ERROR, "VLAN: vlan:async:failed to init netlink cb");
		return;
	}
	nl_cb_err(vlan->cb, NL_CB_CUSTOM, error_handler, vlan);

	vlan->wait_for_iface_cb = &wait_for_iface;
	vlan->wait_for_iface[0] = '\0';

	eloop_register_read_sock(fd, vlan_configure_netlink_receive, vlan, NULL);
}


void vlan_configure(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;

	vlan->skipStep = 1;
	if (vlan->removing)
		vlan->removing = 0;
	else {
		vlan_configure_setup(vlan, hapd);
		if (tagged_interface)
			ifconfig_up(tagged_interface);

		vlan_configure_run(vlan, hapd);
	}
}


void vlan_deconfigure(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	vlan->removing = 1;
	vlan->skipStep = 1;
	vlan->subsubstate = 0;
	vlan_configure_setup(vlan, hapd);

	if (vlan->wait_for_iface[0]) {
		/* wait_for_iface was left in place so deconfigure starts after cache learned this recently created one */
		eloop_cancel_timeout(&wait_for_iface_cb, vlan, hapd);
		eloop_register_timeout(1, 0, &wait_for_iface_cb, vlan, hapd);
	} else {
		vlan_deconfigure_run(vlan, hapd);
	}
}


void vlan_finish_async(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	if (eloop_cancel_timeout(&wait_for_iface_cb, vlan, hapd))
		wait_for_iface_cb(vlan, hapd);
	else if (vlan->wait_for_iface[0]) /* do not wait during shutdown */
		wait_for_iface_cb(vlan, hapd);
	else
		assert(0);
}

