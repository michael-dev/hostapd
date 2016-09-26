#ifndef HOSTAPD_MACVLAN_H
#define HOSTAPD_MACVLAN_H

#ifdef CONFIG_LIBNL3_ROUTE

/* create or reuse macvlan interface if_name
 * @param if_name  macvlan interface name, may be altered
 * @param len      size of if_name buffer
 * @param addr     hw ether address
 * @param if_base  macvlan lowerdev
 *
 * @returns negative error code or 0 on success
 */
int macvlan_add(struct hostapd_data *hapd, char *if_name, size_t len,
		const u8 *addr, const char *if_base);

int macvlan_del(struct hostapd_data *hapd, const char *if_name);

#endif /* CONFIG_LIBNL3_ROUTE */

#endif
