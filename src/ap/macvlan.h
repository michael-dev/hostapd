#ifndef HOSTAPD_MACVLAN_H
#define HOSTAPD_MACVLAN_H

#ifdef CONFIG_LIBNL3_ROUTE
int macvlan_add(const char *if_name, const u8 *addr, const char *if_base);
int macvlan_del(const char *if_name);
#endif /* CONFIG_LIBNL3_ROUTE */

#endif
