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
#include "bridge.h"
#include "ifconfig.h"

#include "utils/common.h"
#include "hostapd.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "vlan_init.h"
#ifdef CONFIG_VLAN_NETLINK
#include "vlan_util.h"
#else
#include "vlan_ioctl.h"
#endif

#include "utils/eloop.h"
#include "vlan_if.h"
#include "vlan_iface.h"
#include "vlan_script.h"

int vlan_if_remove(struct hostapd_data *hapd, struct hostapd_vlan *vlan);

char* itoa(int i)
{
	static char buf[20];
	os_snprintf(buf, sizeof(buf), "%d", i);
	return buf;
}


static void vlan_newlink_tagged(int vlan_naming, char* tagged_interface,
				char* br_name, int vid,
				struct hostapd_data *hapd)
{
	char vlan_ifname[IFNAMSIZ];
	int clean;
	char *script = hapd->conf->ssid.vlan_script;

	if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
		os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s.%d",
			     tagged_interface,  vid);
	else
		os_snprintf(vlan_ifname, sizeof(vlan_ifname), "vlan%d",
			     vid);

	clean = 0;
	ifconfig_up(tagged_interface);

	if (script) {
		if (!run_script(NULL, 0, script, "br_addif", br_name, tagged_interface, "tagged", itoa(vid)))
			clean |= DVLAN_CLEAN_VLAN_PORT;
	} else {
		if (!vlan_add(tagged_interface, vid, vlan_ifname))
			clean |= DVLAN_CLEAN_VLAN;

		if (!br_addif(br_name, vlan_ifname))
			clean |= DVLAN_CLEAN_VLAN_PORT;
	}

	dyn_iface_get(vlan_ifname, "", clean, hapd);

	ifconfig_up(vlan_ifname);
}

static void vlan_bridge_name(char *br_name, struct hostapd_data *hapd, int vid)
{
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	char *script = hapd->conf->ssid.vlan_script;

	if (script && !run_script(br_name, IFNAMSIZ, script, "br_name", hapd->conf->vlan_bridge, tagged_interface, itoa(vid)))
		return;

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


static void vlan_get_bridge(char *br_name, struct hostapd_data *hapd, int vid)
{
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char *script = hapd->conf->ssid.vlan_script;
	int ret;

	if (!script)
		ret = br_addbr(br_name);
	else
		ret = run_script(NULL, 0, script, "br_addbr", br_name, itoa(vid));

	if (!ret)
		dyn_iface_get(br_name, "", DVLAN_CLEAN_BR, hapd);
	else
		dyn_iface_get(br_name, "", 0, hapd);

	ifconfig_up(br_name);

	if (tagged_interface)
		vlan_newlink_tagged(vlan_naming, tagged_interface, br_name,
				    vid, hapd);
}

void vlan_configure(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	char br_name[IFNAMSIZ];
	int untagged, *tagged, i, notempty;
	char *script = hapd->conf->ssid.vlan_script;
	int ret;
	char *ifname;


	ifname = vlan->ifname;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_newlink(%s)", ifname);

	notempty = vlan->vlan_desc.notempty;
	untagged = vlan->vlan_desc.untagged;
	tagged = vlan->vlan_desc.tagged;

	if (!notempty) {
		/* non-VLAN sta */
		if (hapd->conf->bridge[0]) {
			if (script)
				ret = run_script(NULL, 0, script, "br_addif", hapd->conf->bridge, ifname);
			else
				ret = br_addif(hapd->conf->bridge, ifname);
			if (!ret)
				vlan->clean |= DVLAN_CLEAN_WLAN_PORT;
		}
	} else if (untagged > 0 && untagged <= MAX_VLAN_ID) {
		vlan_bridge_name(br_name, hapd, untagged);

		vlan_get_bridge(br_name, hapd, untagged);

		if (script)
			ret = run_script(NULL, 0, script, "br_addif", br_name, ifname, "untagged", itoa(untagged));
		else
			ret = br_addif(br_name, ifname);
		if (!ret)
			vlan->clean |= DVLAN_CLEAN_WLAN_PORT;
	}

	for (i = 0; i < MAX_NUM_TAGGED_VLAN && tagged[i]; i++) {
		if (tagged[i] == untagged)
			continue;
		if (tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID)
			continue;
		if (i > 0 && tagged[i] == tagged[i-1])
			continue;
		vlan_bridge_name(br_name, hapd, tagged[i]);
		vlan_get_bridge(br_name, hapd, tagged[i]);
		vlan_newlink_tagged(DYNAMIC_VLAN_NAMING_WITH_DEVICE,
				    ifname, br_name, tagged[i], hapd);
	}

}

static void vlan_dellink_tagged(int vlan_naming, char* tagged_interface,
				char* br_name, int vid,
				struct hostapd_data *hapd)
{
	char vlan_ifname[IFNAMSIZ];
	int clean;
	char *script = hapd->conf->ssid.vlan_script;

	if (vlan_naming ==  DYNAMIC_VLAN_NAMING_WITH_DEVICE)
		os_snprintf(vlan_ifname, sizeof(vlan_ifname), "%s.%d",
			     tagged_interface,  vid);
	else
		os_snprintf(vlan_ifname, sizeof(vlan_ifname), "vlan%d",
			     vid);

	clean = dyn_iface_put(vlan_ifname, "", hapd);

	if (script) {
		if (clean & DVLAN_CLEAN_VLAN_PORT)
			run_script(NULL, 0, script, "br_delif", br_name, tagged_interface, "tagged", itoa(vid));
	} else {
		if (clean & DVLAN_CLEAN_VLAN_PORT)
			br_delif(br_name, vlan_ifname);

		if (clean & DVLAN_CLEAN_VLAN) {
			ifconfig_down(vlan_ifname);
			vlan_rem(vlan_ifname);
		}
	}
}

static void vlan_put_bridge(char *br_name, struct hostapd_data *hapd, int vid)
{
	int clean;
	char *tagged_interface = hapd->conf->ssid.vlan_tagged_interface;
	int vlan_naming = hapd->conf->ssid.vlan_naming;
	char *script = hapd->conf->ssid.vlan_script;

	if (tagged_interface)
		vlan_dellink_tagged(vlan_naming, tagged_interface, br_name,
				    vid, hapd);

	clean = dyn_iface_put(br_name, "", hapd);

	if (!(clean & DVLAN_CLEAN_BR))
		return;
	if (!script && br_getnumports(br_name) != 0)
		return;

	ifconfig_down(br_name);

	if (script)
		run_script(NULL, 0, script, "br_delbr", br_name, itoa(vid));
	else
		br_delbr(br_name);
}

void vlan_deconfigure(struct hostapd_vlan *vlan, struct hostapd_data *hapd)
{
	char br_name[IFNAMSIZ];
	int untagged, i, *tagged, notempty;
	char *script = hapd->conf->ssid.vlan_script;
	char *ifname = vlan->ifname;
	struct hostapd_vlan *first, *prev, *curr = hapd->conf->vlan;

	wpa_printf(MSG_DEBUG, "VLAN: vlan_dellink(%s)", ifname);

	notempty = vlan->vlan_desc.notempty;
	untagged = vlan->vlan_desc.untagged;
	tagged = vlan->vlan_desc.tagged;

	for (i = 0; i < MAX_NUM_TAGGED_VLAN && tagged[i]; i++) {
		if (tagged[i] == untagged)
			continue;
		if (tagged[i] <= 0 || tagged[i] > MAX_VLAN_ID)
			continue;
		if (i > 0 && tagged[i] == tagged[i-1])
			continue;
		vlan_bridge_name(br_name, hapd, tagged[i]);
		vlan_dellink_tagged(DYNAMIC_VLAN_NAMING_WITH_DEVICE,
				    ifname, br_name, tagged[i], hapd);
		vlan_put_bridge(br_name, hapd, tagged[i]);
	}

	if (!notempty) {
		/* non-VLAN sta */
		if (hapd->conf->bridge[0] && vlan->clean & DVLAN_CLEAN_WLAN_PORT) {
			if (script)
				run_script(NULL, 0, script, "br_delif", hapd->conf->bridge, ifname);
			else
				br_delif(hapd->conf->bridge, ifname);
		}
	} else if (untagged > 0 && untagged <= MAX_VLAN_ID) {
		vlan_bridge_name(br_name, hapd, untagged);

		if (vlan->clean & DVLAN_CLEAN_WLAN_PORT) {
			if (script)
				run_script(NULL, 0, script, "br_delif", br_name, vlan->ifname, "untagged", itoa(untagged));
			else
				br_delif(br_name, vlan->ifname);
		}

		vlan_put_bridge(br_name, hapd, untagged);
	}

	vlan_drop_and_free(vlan, hapd);
}
