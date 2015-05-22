/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005, Devicescape Software, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef VLAN_INIT_H
#define VLAN_INIT_H

#ifndef CONFIG_NO_VLAN
int vlan_init(struct hostapd_data *hapd);
void vlan_deinit(struct hostapd_data *hapd);
struct hostapd_vlan * vlan_add_dynamic(struct hostapd_data *hapd,
				       struct hostapd_vlan *vlan,
				       int vlan_id,
				       struct vlan_description vlan_desc);
void vlan_get_dynamic(struct hostapd_data *hapd, struct hostapd_vlan *vlan);
int vlan_setup_dynamic(struct hostapd_data *hapd, struct hostapd_vlan *vlan);
int vlan_remove_dynamic(struct hostapd_data *hapd, int vlan_id);
int vlan_global_init(struct hapd_interfaces *interfaces);
void vlan_global_deinit(struct hapd_interfaces *interfaces);

#else /* CONFIG_NO_VLAN */
static inline int vlan_init(struct hostapd_data *hapd)
{
	return 0;
}

static inline void vlan_deinit(struct hostapd_data *hapd)
{
}

static inline struct hostapd_vlan *
vlan_add_dynamic(struct hostapd_data *hapd,
		 struct hostapd_vlan *vlan,
		 int vlan_id,
		 struct vlan_description vlan_desc)
{
	return NULL;
}

static inline void vlan_get_dynamic(struct hostapd_data *hapd,
				    struct hostapd_vlan *vlan)
{
}

static inline int vlan_setup_dynamic(struct hostapd_data *hapd,
				     struct hostapd_vlan *vlan)
{
	return -1;
}

static inline int vlan_remove_dynamic(struct hostapd_data *hapd, int vlan_id)
{
	return -1;
}

static inline int vlan_global_init(struct hapd_interfaces *interfaces)
{
	return 0;
}

static inline void vlan_global_deinit(struct hapd_interfaces *interfaces)
{
}

#endif /* CONFIG_NO_VLAN */

#endif /* VLAN_INIT_H */
