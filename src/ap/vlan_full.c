/*
 * hostapd / VLAN initialization - full dynamic VLAN
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include <net/if.h>
/* Avoid conflicts due to NetBSD net/if.h if_type define with driver.h */
#undef if_type
#include <sys/ioctl.h>

#include "utils/common.h"
#include "drivers/netlink.h"
#include "drivers/priv_netlink.h"
#include "drivers/linux_ioctl.h"
#include "common/linux_bridge.h"
#include "common/linux_vlan.h"
#include "utils/eloop.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "wpa_auth.h"
#include "vlan_init.h"
#include "vlan_util.h"


struct full_dynamic_vlan {
	struct netlink_data * nl; /* listens for NEWLINK and DELLINK */
	struct hapd_interfaces *interfaces;
};

static struct full_dynamic_vlan *priv = NULL;

struct vlan_handle_read_ifname_data {
	char ifname[IFNAMSIZ + 1];
	int del;
};

#define DVLAN_CLEAN_BR         0x1
#define DVLAN_CLEAN_VLAN       0x2
#define DVLAN_CLEAN_VLAN_PORT  0x4

struct dynamic_iface {
	char ifname[IFNAMSIZ + 1];
	int usage;
	int clean;
	struct dynamic_iface *next;
};


/* Increment ref counter for ifname and add clean flag.
 * If not in list, add it only if some flags are given.
 */
static void dyn_iface_get(struct hostapd_data *hapd, const char *ifname,
			  int clean)
{
	struct dynamic_iface *next, **dynamic_ifaces;
	struct hapd_interfaces *interfaces;

	interfaces = hapd->iface->interfaces;
	dynamic_ifaces = &interfaces->vlan_priv;

	for (next = *dynamic_ifaces; next; next = next->next) {
		if (os_strcmp(ifname, next->ifname) == 0)
			break;
	}

	if (next) {
		next->usage++;
		next->clean |= clean;
		return;
	}

	if (!clean)
		return;

	next = os_zalloc(sizeof(*next));
	if (!next)
		return;
	os_strlcpy(next->ifname, ifname, sizeof(next->ifname));
	next->usage = 1;
	next->clean = clean;
	next->next = *dynamic_ifaces;
	*dynamic_ifaces = next;
}


/* Decrement reference counter for given ifname.
 * Return clean flag iff reference counter was decreased to zero, else zero
 */
static int dyn_iface_put(struct hostapd_data *hapd, const char *ifname)
{
	struct dynamic_iface *next, *prev = NULL, **dynamic_ifaces;
	struct hapd_interfaces *interfaces;
	int clean;

	interfaces = hapd->iface->interfaces;
	dynamic_ifaces = &interfaces->vlan_priv;

	for (next = *dynamic_ifaces; next; next = next->next) {
		if (os_strcmp(ifname, next->ifname) == 0)
			break;
		prev = next;
	}

	if (!next)
		return 0;

	next->usage--;
	if (next->usage)
		return 0;

	if (prev)
		prev->next = next->next;
	else
		*dynamic_ifaces = next->next;
	clean = next->clean;
	os_free(next);

	return clean;
}


static int ifconfig_down(const char *if_name)
{
	wpa_printf(MSG_DEBUG, "VLAN: Set interface %s down", if_name);
	return ifconfig_helper(if_name, 0);
}


/* This value should be 256 ONLY. If it is something else, then hostapd
 * might crash!, as this value has been hard-coded in 2.4.x kernel
 * bridging code.
 */
#define MAX_BR_PORTS      		256

static int br_delif(const char *br_name, const char *if_name)
{
	int fd;
	struct ifreq ifr;
	unsigned long args[2];
	int if_index;

	wpa_printf(MSG_DEBUG, "VLAN: br_delif(%s, %s)", br_name, if_name);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: socket(AF_INET,SOCK_STREAM) "
			   "failed: %s", __func__, strerror(errno));
		return -1;
	}

	if (linux_br_del_if(fd, br_name, if_name) == 0)
		goto done;

	if_index = if_nametoindex(if_name);

	if (if_index == 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: Failure determining "
			   "interface index for '%s'",
			   __func__, if_name);
		close(fd);
		return -1;
	}

	args[0] = BRCTL_DEL_IF;
	args[1] = if_index;

	os_strlcpy(ifr.ifr_name, br_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (void *) args;

	if (ioctl(fd, SIOCDEVPRIVATE, &ifr) < 0 && errno != EINVAL) {
		/* No error if interface already removed. */
		wpa_printf(MSG_ERROR, "VLAN: %s: ioctl[SIOCDEVPRIVATE,"
			   "BRCTL_DEL_IF] failed for br_name=%s if_name=%s: "
			   "%s", __func__, br_name, if_name, strerror(errno));
		close(fd);
		return -1;
	}

done:
	close(fd);
	return 0;
}


/*
	Add interface 'if_name' to the bridge 'br_name'

	returns -1 on error
	returns 1 if the interface is already part of the bridge
	returns 0 otherwise
*/
static int br_addif(const char *br_name, const char *if_name)
{
	int fd;
	struct ifreq ifr;
	unsigned long args[2];
	int if_index;

	wpa_printf(MSG_DEBUG, "VLAN: br_addif(%s, %s)", br_name, if_name);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: socket(AF_INET,SOCK_STREAM) "
			   "failed: %s", __func__, strerror(errno));
		return -1;
	}

	if (linux_br_add_if(fd, br_name, if_name) == 0)
		goto done;
	if (errno == EBUSY) {
		/* The interface is already added. */
		close(fd);
		return 1;
	}

	if_index = if_nametoindex(if_name);

	if (if_index == 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: Failure determining "
			   "interface index for '%s'",
			   __func__, if_name);
		close(fd);
		return -1;
	}

	args[0] = BRCTL_ADD_IF;
	args[1] = if_index;

	os_strlcpy(ifr.ifr_name, br_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (void *) args;

	if (ioctl(fd, SIOCDEVPRIVATE, &ifr) < 0) {
		if (errno == EBUSY) {
			/* The interface is already added. */
			close(fd);
			return 1;
		}

		wpa_printf(MSG_ERROR, "VLAN: %s: ioctl[SIOCDEVPRIVATE,"
			   "BRCTL_ADD_IF] failed for br_name=%s if_name=%s: "
			   "%s", __func__, br_name, if_name, strerror(errno));
		close(fd);
		return -1;
	}

done:
	close(fd);
	return 0;
}


static int br_delbr(const char *br_name)
{
	int fd;
	unsigned long arg[2];

	wpa_printf(MSG_DEBUG, "VLAN: br_delbr(%s)", br_name);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: socket(AF_INET,SOCK_STREAM) "
			   "failed: %s", __func__, strerror(errno));
		return -1;
	}

	if (linux_br_del(fd, br_name) == 0)
		goto done;

	arg[0] = BRCTL_DEL_BRIDGE;
	arg[1] = (unsigned long) br_name;

	if (ioctl(fd, SIOCGIFBR, arg) < 0 && errno != ENXIO) {
		/* No error if bridge already removed. */
		wpa_printf(MSG_ERROR, "VLAN: %s: BRCTL_DEL_BRIDGE failed for "
			   "%s: %s", __func__, br_name, strerror(errno));
		close(fd);
		return -1;
	}

done:
	close(fd);
	return 0;
}


/*
	Add a bridge with the name 'br_name'.

	returns -1 on error
	returns 1 if the bridge already exists
	returns 0 otherwise
*/
static int br_addbr(const char *br_name)
{
	int fd;
	unsigned long arg[4];
	struct ifreq ifr;

	wpa_printf(MSG_DEBUG, "VLAN: br_addbr(%s)", br_name);
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: socket(AF_INET,SOCK_STREAM) "
			   "failed: %s", __func__, strerror(errno));
		return -1;
	}

	if (linux_br_add(fd, br_name) == 0)
		goto done;
	if (errno == EEXIST) {
		/* The bridge is already added. */
		close(fd);
		return 1;
	}

	arg[0] = BRCTL_ADD_BRIDGE;
	arg[1] = (unsigned long) br_name;

	if (ioctl(fd, SIOCGIFBR, arg) < 0) {
		if (errno == EEXIST) {
			/* The bridge is already added. */
			close(fd);
			return 1;
		} else {
			wpa_printf(MSG_ERROR, "VLAN: %s: BRCTL_ADD_BRIDGE "
				   "failed for %s: %s",
				   __func__, br_name, strerror(errno));
			close(fd);
			return -1;
		}
	}

done:
	/* Decrease forwarding delay to avoid EAPOL timeouts. */
	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, br_name, IFNAMSIZ);
	arg[0] = BRCTL_SET_BRIDGE_FORWARD_DELAY;
	arg[1] = 1;
	arg[2] = 0;
	arg[3] = 0;
	ifr.ifr_data = (char *) &arg;
	if (ioctl(fd, SIOCDEVPRIVATE, &ifr) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: "
			   "BRCTL_SET_BRIDGE_FORWARD_DELAY (1 sec) failed for "
			   "%s: %s", __func__, br_name, strerror(errno));
		/* Continue anyway */
	}

	close(fd);
	return 0;
}


static int br_getnumports(const char *br_name)
{
	int fd;
	int i;
	int port_cnt = 0;
	unsigned long arg[4];
	int ifindices[MAX_BR_PORTS];
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: socket(AF_INET,SOCK_STREAM) "
			   "failed: %s", __func__, strerror(errno));
		return -1;
	}

	arg[0] = BRCTL_GET_PORT_LIST;
	arg[1] = (unsigned long) ifindices;
	arg[2] = MAX_BR_PORTS;
	arg[3] = 0;

	os_memset(ifindices, 0, sizeof(ifindices));
	os_strlcpy(ifr.ifr_name, br_name, sizeof(ifr.ifr_name));
	ifr.ifr_data = (void *) arg;

	if (ioctl(fd, SIOCDEVPRIVATE, &ifr) < 0) {
		wpa_printf(MSG_ERROR, "VLAN: %s: BRCTL_GET_PORT_LIST "
			   "failed for %s: %s",
			   __func__, br_name, strerror(errno));
		close(fd);
		return -1;
	}

	for (i = 1; i < MAX_BR_PORTS; i++) {
		if (ifindices[i] > 0) {
			port_cnt++;
		}
	}

	close(fd);
	return port_cnt;
}


static void vlan_newlink_tagged(int vlan_naming, const char *tagged_interface,
				const char *br_name, int vid,
				struct hostapd_data *hapd)
{
	char vlan_ifname[IFNAMSIZ];
	int clean;
	int ret;

	if (vlan_naming == DYNAMIC_VLAN_NAMING_WITH_DEVICE)
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s.%d",
				  tagged_interface, vid);
	else
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "vlan%d",
				  vid);
	if (ret >= (int) sizeof(vlan_ifname))
		wpa_printf(MSG_WARNING,
			   "VLAN: Interface name was truncated to %s",
			   vlan_ifname);

	clean = 0;
	ifconfig_up(tagged_interface);
	if (!vlan_add(tagged_interface, vid, vlan_ifname))
		clean |= DVLAN_CLEAN_VLAN;

	if (!br_addif(br_name, vlan_ifname))
		clean |= DVLAN_CLEAN_VLAN_PORT;

	dyn_iface_get(hapd, vlan_ifname, clean);

	ifconfig_up(vlan_ifname);
}


static void vlan_bridge_name(char *br_name, struct hostapd_data *hapd,
			     struct hostapd_vlan *vlan, int vid)
{
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	int ret;

	if (vlan->bridge[0]) {
		os_strlcpy(br_name, vlan->bridge, IFNAMSIZ);
		ret = 0;
	} else if (hapd->conf->vlan_bridge[0]) {
		ret = os_snprintf(br_name, IFNAMSIZ, "%s%d",
				  hapd->conf->vlan_bridge, vid);
	} else if (tagged_interface) {
		ret = os_snprintf(br_name, IFNAMSIZ, "br%s.%d",
				  tagged_interface, vid);
	} else {
		ret = os_snprintf(br_name, IFNAMSIZ, "brvlan%d", vid);
	}
	if (ret >= IFNAMSIZ)
		wpa_printf(MSG_WARNING,
			   "VLAN: Interface name was truncated to %s",
			   br_name);
}


static void vlan_get_bridge(const char *br_name, struct hostapd_data *hapd,
			    int vid)
{
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	int vlan_naming = hapd->conf->ssid.vlan_naming;

	dyn_iface_get(hapd, br_name, br_addbr(br_name) ? 0 : DVLAN_CLEAN_BR);

	ifconfig_up(br_name);

	if (tagged_interface)
		vlan_newlink_tagged(vlan_naming, tagged_interface, br_name,
				    vid, hapd);
}


void vlan_newlink(const char *ifname, struct hostapd_data *hapd)
{
	char br_name[IFNAMSIZ];
	struct hostapd_vlan *vlan;
	int untagged, *tagged, i, notempty;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_newlink(%s)", ifname);

	for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
		if (vlan->configured ||
		    os_strcmp(ifname, vlan->ifname) != 0)
			continue;
		break;
	}
	if (!vlan)
		return;

	vlan->configured = 1;

	notempty = vlan->vlan_desc.notempty;
	untagged = vlan->vlan_desc.untagged;
	tagged = vlan->vlan_desc.tagged;

	if (!notempty) {
		/* Non-VLAN STA */
		if (hapd->conf->bridge[0] &&
		    !br_addif(hapd->conf->bridge, ifname))
			vlan->clean |= DVLAN_CLEAN_WLAN_PORT;
	} else if (untagged > 0 && untagged <= MAX_VLAN_ID) {
		vlan_bridge_name(br_name, hapd, vlan, untagged);

		vlan_get_bridge(br_name, hapd, untagged);

		if (!br_addif(br_name, ifname))
			vlan->clean |= DVLAN_CLEAN_WLAN_PORT;
	}

	for (i = 0; i < MAX_NUM_TAGGED_VLAN && tagged[i]; i++) {
		if (tagged[i] == untagged ||
		    tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID ||
		    (i > 0 && tagged[i] == tagged[i - 1]))
			continue;
		vlan_bridge_name(br_name, hapd, vlan, tagged[i]);
		vlan_get_bridge(br_name, hapd, tagged[i]);
		vlan_newlink_tagged(DYNAMIC_VLAN_NAMING_WITH_DEVICE,
				    ifname, br_name, tagged[i], hapd);
	}

	ifconfig_up(ifname);
}


static void vlan_dellink_tagged(int vlan_naming, const char *tagged_interface,
				const char *br_name, int vid,
				struct hostapd_data *hapd)
{
	char vlan_ifname[IFNAMSIZ];
	int clean;
	int ret;

	if (vlan_naming == DYNAMIC_VLAN_NAMING_WITH_DEVICE)
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s.%d",
				  tagged_interface, vid);
	else
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "vlan%d",
				  vid);
	if (ret >= (int) sizeof(vlan_ifname))
		wpa_printf(MSG_WARNING,
			   "VLAN: Interface name was truncated to %s",
			   vlan_ifname);


	clean = dyn_iface_put(hapd, vlan_ifname);

	if (clean & DVLAN_CLEAN_VLAN_PORT)
		br_delif(br_name, vlan_ifname);

	if (clean & DVLAN_CLEAN_VLAN) {
		ifconfig_down(vlan_ifname);
		vlan_rem(vlan_ifname);
	}
}


static void vlan_put_bridge(const char *br_name, struct hostapd_data *hapd,
			    int vid)
{
	int clean;
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	int vlan_naming = hapd->conf->ssid.vlan_naming;

	if (tagged_interface)
		vlan_dellink_tagged(vlan_naming, tagged_interface, br_name,
				    vid, hapd);

	clean = dyn_iface_put(hapd, br_name);
	if ((clean & DVLAN_CLEAN_BR) && br_getnumports(br_name) == 0) {
		ifconfig_down(br_name);
		br_delbr(br_name);
	}
}


void vlan_dellink(const char *ifname, struct hostapd_data *hapd)
{
	struct hostapd_vlan *first, *prev, *vlan = hapd->conf->vlan;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_dellink(%s)", ifname);

	first = prev = vlan;

	while (vlan) {
		if (os_strcmp(ifname, vlan->ifname) != 0) {
			prev = vlan;
			vlan = vlan->next;
			continue;
		}
		break;
	}
	if (!vlan)
		return;

	if (vlan->configured) {
		int notempty = vlan->vlan_desc.notempty;
		int untagged = vlan->vlan_desc.untagged;
		int *tagged = vlan->vlan_desc.tagged;
		char br_name[IFNAMSIZ];
		int i;

		for (i = 0; i < MAX_NUM_TAGGED_VLAN && tagged[i]; i++) {
			if (tagged[i] == untagged ||
			    tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID ||
			    (i > 0 && tagged[i] == tagged[i - 1]))
				continue;
			vlan_bridge_name(br_name, hapd, vlan, tagged[i]);
			vlan_dellink_tagged(DYNAMIC_VLAN_NAMING_WITH_DEVICE,
					    ifname, br_name, tagged[i], hapd);
			vlan_put_bridge(br_name, hapd, tagged[i]);
		}

		if (!notempty) {
			/* Non-VLAN STA */
			if (hapd->conf->bridge[0] &&
			    (vlan->clean & DVLAN_CLEAN_WLAN_PORT))
				br_delif(hapd->conf->bridge, ifname);
		} else if (untagged > 0 && untagged <= MAX_VLAN_ID) {
			vlan_bridge_name(br_name, hapd, vlan, untagged);

			if (vlan->clean & DVLAN_CLEAN_WLAN_PORT)
				br_delif(br_name, vlan->ifname);

			vlan_put_bridge(br_name, hapd, untagged);
		}
	}

	/*
	 * Ensure this VLAN interface is actually removed even if
	 * NEWLINK message is only received later.
	 */
	if (if_nametoindex(vlan->ifname) && vlan_if_remove(hapd, vlan))
		wpa_printf(MSG_ERROR,
			   "VLAN: Could not remove VLAN iface: %s: %s",
			   vlan->ifname, strerror(errno));

	if (vlan == first)
		hapd->conf->vlan = vlan->next;
	else
		prev->next = vlan->next;

	os_free(vlan);
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
 
static void
vlan_event_receive(void *ctx, struct ifinfomsg *ifi, struct rtattr *attr,
		   size_t attrlen, int del)
{
	struct vlan_handle_read_ifname_data data;
	data.del = del;
	data.ifname[0] = '\0';

	if (!priv ||
	    !priv->interfaces ||
	    !priv->interfaces->for_each_interface)
		return;

	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_IFNAME) {
			size_t n = RTA_PAYLOAD(attr);
			if (n > sizeof(data.ifname))
				break;
			os_strlcpy(data.ifname, RTA_DATA(attr), n);
			break;
		}
		attr = RTA_NEXT(attr, attrlen);
	}

	if (!data.ifname[0])
		return;
	if (data.del && if_nametoindex(data.ifname))
	    /* interface still exists, race condition ->
	     * iface has just been recreated */
		return;
	priv->interfaces->for_each_interface(
			priv->interfaces,
			vlan_handle_read_ifname,
			&data);
}


static void
vlan_event_receive_newlink(void *ctx, struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	vlan_event_receive(ctx, ifi, (struct rtattr *) buf, len, 0);
}


static void
vlan_event_receive_dellink(void *ctx, struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	vlan_event_receive(ctx, ifi, (struct rtattr *) buf, len, 1);
}


void full_dynamic_vlan_init(struct hostapd_data *hapd)
{
	vlan_set_name_type(hapd->conf->ssid.vlan_naming ==
			   DYNAMIC_VLAN_NAMING_WITH_DEVICE ?
			   VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD :
			   VLAN_NAME_TYPE_PLUS_VID_NO_PAD);
}


int vlan_global_init(struct hapd_interfaces *interfaces)
{
	struct netlink_config *cfg = NULL;

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		goto err;

	cfg->ctx = NULL;
	cfg->newlink_cb = vlan_event_receive_newlink;
	cfg->dellink_cb = vlan_event_receive_dellink;

	priv = os_zalloc(sizeof(*priv));
	if (priv == NULL)
		goto err;

	priv->interfaces = interfaces;
	priv->nl = netlink_init(cfg);
	if (priv->nl == NULL)
	{
		wpa_printf(MSG_ERROR, "VLAN: %s: netlink_init failed: %s",
			   __func__, strerror(errno));
		goto err;
	}

	return 0;
err:
	if (priv)
	{
		os_free(priv);
		priv = NULL;
	}
	if (cfg)
	{
		os_free(cfg);
		cfg = NULL;
	}
	return -1;
}

void full_dynamic_vlan_deinit(struct hostapd_data *hapd)
{
}


void vlan_global_deinit()
{
	if (priv == NULL)
		return;
	netlink_deinit(priv->nl);
	os_free(priv);
	priv = NULL;
}

