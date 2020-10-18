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
#ifdef CONFIG_RSN_PREAUTH_COPY
#include "preauth_auth.h"
#endif /* CONFIG_RSN_PREAUTH_COPY */


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
#define DVLAN_CLEAN_VID        0x8

struct dynamic_iface {
	char ifname[IFNAMSIZ + 1];
	int vid;
	int usage;
	int clean;
	struct dynamic_iface *next;
};


static struct dynamic_iface *
dyn_iface_find(struct hostapd_data *hapd, const char *ifname, const int vid)
{
	struct dynamic_iface *next, **dynamic_ifaces;

	dynamic_ifaces = &hapd->iface->interfaces->vlan_priv;

	for (next = *dynamic_ifaces; next; next = next->next) {
		if (os_strcmp(ifname, next->ifname) == 0 &&
		    vid == next->vid)
			break;
	}

	return next;
}

/* Increment ref counter for ifname and add clean flag.
 * If not in list, add it only if some flags are given.
 * next is output from dyn_iface_find.
 */
static void
dyn_iface_get(struct hostapd_data *hapd, const char *ifname, const int vid,
	      const int clean, struct dynamic_iface *next)
{
	struct dynamic_iface **dynamic_ifaces;

	dynamic_ifaces = &hapd->iface->interfaces->vlan_priv;

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
	next->vid = vid;
	next->usage = 1;
	next->clean = clean;
	next->next = *dynamic_ifaces;
	*dynamic_ifaces = next;
}


/* Decrement reference counter for given ifname.
 * Return clean flag iff reference counter was decreased to zero, else zero
 */
static int
dyn_iface_put(struct hostapd_data *hapd, const char *ifname, const int vid)
{
	struct dynamic_iface *next, *prev = NULL, **dynamic_ifaces;
	int clean;

	dynamic_ifaces = &hapd->iface->interfaces->vlan_priv;

	for (next = *dynamic_ifaces; next; next = next->next) {
		if (os_strcmp(ifname, next->ifname) == 0 &&
		    vid == next->vid)
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


#ifdef HAVE_LINUX_IOCTL
static int br_delif(const char *br_name, const char *if_name)
{
	int fd;
	int err;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	err = linux_br_del_if(fd, br_name, if_name);

	linux_ioctl_close(fd);

	return err;
}

static int br_addif(const char *br_name, const char *if_name)
{
	int fd;
	int err;
	char old_bridge[IFNAMSIZ+1];

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	os_memset(old_bridge, 0, sizeof(old_bridge));
	err = linux_br_get(old_bridge, if_name);
	if (err || os_strcmp(old_bridge, br_name))
		err = linux_br_add_if(fd, br_name, if_name);
	else
		err = -1; // already in bridge

	linux_ioctl_close(fd);

	return err;
}

static int br_delbr(const char *br_name)
{
	int fd;
	int err;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	err = linux_br_del(fd, br_name);

	linux_ioctl_close(fd);

	return err;
}

static int br_addbr(const char *br_name)
{
	int fd;
	int err = -1;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	if (linux_br_exists(fd, br_name) > 0)
		goto out;

	err = linux_br_add(fd, br_name);
out:
	linux_ioctl_close(fd);

	return err;
}

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
static int br_vlan_filtering(const char *br_name, int enable, int pvid)
{
	int fd;
	int err;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	err = linux_br_vlan_filtering(fd, br_name, enable, pvid);

	linux_ioctl_close(fd);

	return err;
}

/*
 * 0: disabled
 * 1: enabled
 * 2: add cache
 * 3: del cache
 * 4: committing
 */
static int br_vlan_cache_state = 0;

static struct vlan_description *br_vlan_cache[2];
static int br_vlan_cache_num_tagged[2] = {0, 0};
static char br_vlan_cache_ifname[2][IFNAMSIZ+1] = {};

static void br_vlan_cache_prepare() {
	int i;
	if (br_vlan_cache_state)
		return;

	for (i = 0; i < 2; i++) {
		br_vlan_cache[i] = os_zalloc(sizeof(struct vlan_description));
		if (!br_vlan_cache[i])
			goto free;
	}

	br_vlan_cache_state = 1;
	return;
free:
	for (; i >= 0; i--) {
		os_free(br_vlan_cache[i]);
		br_vlan_cache[i] = NULL;
	}
	return;
}

static int
br_vlan_cache_add(const int type, const char *if_name, int untagged,
		  int numtagged, int *tagged)
{
	int idx, i;

	if (if_name[0] == '\0')
		return -1;

	if (br_vlan_cache_state == 1)
		br_vlan_cache_state = type;
	if (br_vlan_cache_state != type)
		return -1;

	for (idx = 0; idx < 2; idx++) {
		if (br_vlan_cache_ifname[idx][0] == '\0') {
			os_strlcpy(br_vlan_cache_ifname[idx], if_name,
				   IFNAMSIZ+1);
			break;
		}
		if (os_strcmp(br_vlan_cache_ifname[idx], if_name) == 0)
			break;
	}
	if (idx >= 2)
		return -1;

	if (br_vlan_cache_num_tagged[idx] + numtagged > MAX_NUM_TAGGED_VLAN)
		return -1;

	if (untagged)
		br_vlan_cache[idx]->untagged = untagged;

	for (i = 0; i < numtagged; i++) {
		int j = br_vlan_cache_num_tagged[idx]++;
		br_vlan_cache[idx]->tagged[j] = tagged[i];
	}

	br_vlan_cache[idx]->notempty = 1;

	return 0;
}

static int
br_vlan_add(const char *if_name, int untagged, int numtagged, int *tagged)
{
	int fd;
	int err;

	if (br_vlan_cache_add(2, if_name, untagged, numtagged, tagged) >= 0)
		return 0;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	wpa_printf(MSG_WARNING, "VLAN: Interface %s configured to vlan %d%s in br_vlan_add",
		   if_name, untagged, (numtagged > 0 && tagged[0]) ? "+" : "");

	err = linux_br_add_vlan(fd, if_name, untagged, numtagged, tagged);

	linux_ioctl_close(fd);

	return err;
}

static int
br_vlan_del(const char *if_name, int untagged, int numtagged, int *tagged)
{
	int fd;
	int err;

	if (br_vlan_cache_add(3, if_name, untagged, numtagged, tagged) >= 0)
		return 0;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;

	err = linux_br_del_vlan(fd, if_name, untagged, numtagged, tagged);

	linux_ioctl_close(fd);

	return err;
}

static void br_vlan_cache_commit() {
	int i, mode;

	if (br_vlan_cache_state == 0)
		return;

	mode = br_vlan_cache_state;
	br_vlan_cache_state = 4;

	for (i = 0; i < 2; i++) {
		if (!br_vlan_cache[i]->notempty)
			continue;
		if (mode == 2) {
			br_vlan_add(br_vlan_cache_ifname[i],
				    br_vlan_cache[i]->untagged,
				    br_vlan_cache_num_tagged[i],
				    br_vlan_cache[i]->tagged);
		}
		if (mode == 3) {
			br_vlan_del(br_vlan_cache_ifname[i],
				    br_vlan_cache[i]->untagged,
				    br_vlan_cache_num_tagged[i],
				    br_vlan_cache[i]->tagged);
		}
	}

	for (i = 0; i < 2; i++) {
		os_free(br_vlan_cache[i]);
		br_vlan_cache[i] = NULL;
		br_vlan_cache_num_tagged[i] = 0;
		br_vlan_cache_ifname[i][0] = '\0';
	}

	br_vlan_cache_state = 0;
}
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

static int br_getnumports(const char *br_name)
{
	int fd;
	int ret;

	fd = linux_ioctl_socket();
	if (fd < 0)
		return -1;
	ret = linux_br_getnumports(fd, br_name);

	linux_ioctl_close(fd);

	return ret;
}

#else /* HAVE_LINUX_IOCTL */
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
#endif // HAVE_LINUX_IOCTL


static void vlan_newlink_tagged(int vlan_naming, const char *tagged_interface,
				const char *br_name, int vid,
				struct hostapd_data *hapd, int vlan_filtering)
{
	char vlan_ifname[IFNAMSIZ];
	int clean;
	int ret;
	struct dynamic_iface *ref = NULL;


	if (vlan_filtering)
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s",
				  tagged_interface);
	else if (vlan_naming == DYNAMIC_VLAN_NAMING_WITH_DEVICE)
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
	/* vlan_filtering implies vlan_ifname == tagged_interface, already present,
	 * so nothing to add here */
	if (!vlan_filtering &&
	    !vlan_add(tagged_interface, vid, vlan_ifname))
		clean |= DVLAN_CLEAN_VLAN;

	ref = dyn_iface_find(hapd, vlan_ifname, 0);
	/* add iface to bridge if it shouldn't be there */
	if (!ref && !br_addif(br_name, vlan_ifname))
		clean |= DVLAN_CLEAN_VLAN_PORT;
	dyn_iface_get(hapd, vlan_ifname, 0, clean, ref);

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	if (vlan_filtering) {
		ref = dyn_iface_find(hapd, vlan_ifname, vid);
		if (!ref)
			br_vlan_add(vlan_ifname, 0, 1, &vid);
		/* checking if vlan id was already present is too complicated */
		dyn_iface_get(hapd, vlan_ifname, vid, DVLAN_CLEAN_VID, ref);
	}
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

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
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	} else if (hapd->conf->vlan_bridge[0] && hapd->conf->ssid.bridge_vlan_filtering) {
		ret = os_snprintf(br_name, IFNAMSIZ, "%s",
				  hapd->conf->vlan_bridge);
	} else if (tagged_interface && hapd->conf->ssid.bridge_vlan_filtering) {
		ret = os_snprintf(br_name, IFNAMSIZ, "br%s",
				  tagged_interface);
	} else if (hapd->conf->ssid.bridge_vlan_filtering) {
		ret = os_snprintf(br_name, IFNAMSIZ, "brvlan");
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */
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
	int vlan_filtering, flags = 0;
	struct dynamic_iface *ref = NULL;

	ref = dyn_iface_find(hapd, br_name, 0);
	if (!ref && !br_addbr(br_name))
	       flags |= DVLAN_CLEAN_BR;
	dyn_iface_get(hapd, br_name, 0, flags, ref);
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	vlan_filtering = hapd->conf->ssid.bridge_vlan_filtering;
	if (flags)
		/* toggle vlan filtering and possibly disable default pvid */
		br_vlan_filtering(br_name, vlan_filtering, 0);
#else
	vlan_filtering = 0;
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

	ifconfig_up(br_name);

	if (tagged_interface)
		vlan_newlink_tagged(vlan_naming, tagged_interface, br_name,
				    vid, hapd, vlan_filtering);
}


static void vlan_newlink_real(void *eloop_ctx, void *timeout_ctx);
void vlan_newlink(const char *ifname, struct hostapd_data *hapd)
{
	struct hostapd_vlan *vlan;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_newlink(%s)", ifname);

	for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
		if (vlan->configured ||
		    os_strcmp(ifname, vlan->ifname) != 0)
			continue;
		break;
	}
	if (!vlan)
		return;

	eloop_cancel_timeout(vlan_newlink_real, vlan, hapd);
	eloop_register_timeout(0, 0, vlan_newlink_real, vlan, hapd); // for test suite to pass, 1s is too long
}

static void vlan_newlink_real(void *eloop_ctx, void *timeout_ctx)
{
	int untagged, *tagged, i, notempty, vlan_filtering;
	char br_name[IFNAMSIZ];
	struct hostapd_vlan *vlan = eloop_ctx;
	struct hostapd_data *hapd = timeout_ctx;
	const char* ifname = vlan->ifname;

	vlan->configured = 1;

	notempty = vlan->vlan_desc.notempty;
	untagged = vlan->vlan_desc.untagged;
	tagged = vlan->vlan_desc.tagged;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	vlan_filtering = hapd->conf->ssid.bridge_vlan_filtering;
#else
	vlan_filtering = 0;
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

	if (notempty)
		br_vlan_cache_prepare();

	if (!notempty) {
		/* Non-VLAN STA */
		if (hapd->conf->bridge[0] &&
		    !br_addif(hapd->conf->bridge, ifname))
			vlan->clean |= DVLAN_CLEAN_WLAN_PORT;
	} else if (untagged > 0 && untagged <= MAX_VLAN_ID) {
		vlan_bridge_name(br_name, hapd, vlan, untagged);

		vlan_get_bridge(br_name, hapd, untagged);

		if (!br_addif(br_name, ifname)) {
			vlan->clean |= DVLAN_CLEAN_WLAN_PORT;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
			if (vlan_filtering)
				br_vlan_add(ifname, untagged, 0, NULL);
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */
		}
	}

	for (i = 0; i < MAX_NUM_TAGGED_VLAN && tagged[i]; i++) {
		if (tagged[i] == untagged ||
		    tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID ||
		    (i > 0 && tagged[i] == tagged[i - 1]))
			continue;
		vlan_bridge_name(br_name, hapd, vlan, tagged[i]);
		vlan_get_bridge(br_name, hapd, tagged[i]);
		vlan_newlink_tagged(DYNAMIC_VLAN_NAMING_WITH_DEVICE,
				    ifname, br_name, tagged[i], hapd,
				    vlan_filtering);
	}

	if (notempty)
		br_vlan_cache_commit();

	ifconfig_up(ifname);
	wpa_printf(MSG_WARNING, "VLAN: Interface %s configured to vlan %d%s in vlan_newlink_real",
		   ifname, notempty ? untagged : 0, (notempty && tagged[0]) ? "+" : "");

#ifdef CONFIG_RSN_PREAUTH_COPY
	if (!vlan->rsn_preauth)
		vlan->rsn_preauth = rsn_preauth_snoop_init(hapd, vlan->ifname);
#endif /* CONFIG_RSN_PREAUTH_COPY */
}


static void vlan_dellink_tagged(int vlan_naming, const char *tagged_interface,
				const char *br_name, int vid,
				struct hostapd_data *hapd, int vlan_filtering)
{
	char vlan_ifname[IFNAMSIZ];
	int clean;
	int ret;

	if (vlan_filtering)
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s",
				  tagged_interface);
	else if (vlan_naming == DYNAMIC_VLAN_NAMING_WITH_DEVICE)
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s.%d",
				  tagged_interface, vid);
	else
		ret = os_snprintf(vlan_ifname, sizeof(vlan_ifname), "vlan%d",
				  vid);
	if (ret >= (int) sizeof(vlan_ifname))
		wpa_printf(MSG_WARNING,
			   "VLAN: Interface name was truncated to %s",
			   vlan_ifname);

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	if (vlan_filtering) {
		clean = dyn_iface_put(hapd, vlan_ifname, vid);
		if (clean & DVLAN_CLEAN_VID)
			br_vlan_del(vlan_ifname, 0, 1, &vid);
	}
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

	clean = dyn_iface_put(hapd, vlan_ifname, 0);

	if (clean & DVLAN_CLEAN_VLAN_PORT)
		br_delif(br_name, vlan_ifname);

	if (clean & DVLAN_CLEAN_VLAN) {
		// DVLAN_CLEAN_VLEAN not set by vlan_newlink_tagged if vlan_filtering
		ifconfig_down(vlan_ifname);
		vlan_rem(vlan_ifname);
	}
}


static void vlan_put_bridge(const char *br_name, struct hostapd_data *hapd,
			    int vid)
{
	int clean, vlan_filtering;
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	int vlan_naming = hapd->conf->ssid.vlan_naming;

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	vlan_filtering = hapd->conf->ssid.bridge_vlan_filtering;
#else
	vlan_filtering = 0;
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

	if (tagged_interface)
		vlan_dellink_tagged(vlan_naming, tagged_interface, br_name,
				    vid, hapd, vlan_filtering);

	clean = dyn_iface_put(hapd, br_name, 0);
	if ((clean & DVLAN_CLEAN_BR) && br_getnumports(br_name) == 0) {
		ifconfig_down(br_name);
		br_delbr(br_name);
	}
}


void vlan_dellink(const char *ifname, struct hostapd_data *hapd)
{
	struct hostapd_vlan *first, *prev, *vlan = hapd->conf->vlan;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	const int vlan_filtering = hapd->conf->ssid.bridge_vlan_filtering;
#else
	const int vlan_filtering = 0;
#endif /* CONFIG_BRIDGE_VLAN_FILTERING */

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

	eloop_cancel_timeout(vlan_newlink_real, vlan, hapd);

#ifdef CONFIG_RSN_PREAUTH_COPY
	if (vlan->rsn_preauth) {
		rsn_preauth_snoop_deinit(hapd, vlan->ifname, vlan->rsn_preauth);
		vlan->rsn_preauth = NULL;
	}
#endif /* CONFIG_RSN_PREAUTH_COPY */

	if (vlan->configured) {
		int notempty = vlan->vlan_desc.notempty;
		int untagged = vlan->vlan_desc.untagged;
		int *tagged = vlan->vlan_desc.tagged;
		char br_name[IFNAMSIZ];
		int i;

		if (notempty)
			br_vlan_cache_prepare();

		for (i = 0; i < MAX_NUM_TAGGED_VLAN && tagged[i]; i++) {
			if (tagged[i] == untagged ||
			    tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID ||
			    (i > 0 && tagged[i] == tagged[i - 1]))
				continue;
			vlan_bridge_name(br_name, hapd, vlan, tagged[i]);
			vlan_dellink_tagged(DYNAMIC_VLAN_NAMING_WITH_DEVICE,
					    ifname, br_name, tagged[i], hapd,
					    vlan_filtering);
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

		if (notempty)
			br_vlan_cache_commit();
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

