#ifndef VLAN_PRIV_H
#define VLAN_PRIV_H

#define VLAN_EVENT_NEWLINK   1
#define VLAN_EVENT_DELLINK   2
#define VLAN_EVENT_IFF_UP    3
#define VLAN_EVENT_IFF_DOWN  4
#define VLAN_EVENT_SLAVE     5
#define VLAN_EVENT_MASTER    6

struct hostapd_vlan_data {
	struct dynamic_iface *dynamic_ifaces;
#ifdef CONFIG_VLAN_ASYNC
	struct nl_cache_mngr *linkcachemngr;
	struct nl_cache *linkcache;
#endif /* CONFIG_VLAN_ASYNC */
};

int vlan_if_remove(struct hostapd_data *hapd, struct hostapd_vlan *vlan);
void vlan_drop_and_free(struct hostapd_vlan *vlan, struct hostapd_data *hapd);

#endif /* VLAN_PRIV_H */
