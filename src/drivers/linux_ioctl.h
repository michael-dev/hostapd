/*
 * Linux ioctl helper functions for driver wrappers
 * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef LINUX_IOCTL_H
#define LINUX_IOCTL_H

int linux_set_iface_flags(int sock, const char *ifname, int dev_up);
int linux_iface_up(int sock, const char *ifname);
int linux_get_ifhwaddr(int sock, const char *ifname, u8 *addr);
int linux_set_ifhwaddr(int sock, const char *ifname, const u8 *addr);
int linux_br_add(int sock, const char *brname);
int linux_br_del(int sock, const char *brname);
int linux_br_add_if(int sock, const char *brname, const char *ifname);
int linux_br_del_if(int sock, const char *brname, const char *ifname);
int linux_br_get(char *brname, const char *ifname);
int linux_br_getnumports(int sock, const char *br_name);
int linux_master_get(char *master_ifname, const char *ifname);
#ifdef HAVE_LINUX_IOCTL_NEWLINK
int linux_br_exists(int sock, const char *br_name);
int linux_br_vlan_filtering(int sock, const char *brname, int vlan_filtering,
			    int pvid);
int linux_br_add_vlan(int sock, const char *ifname, int untagged, int numtagged,
		      int *tagged);
int linux_br_del_vlan(int sock, const char *ifname, int untagged, int numtagged,
		      int *tagged);
int linux_br_fdb_add(int sock, const char *br_name, const u8* mac);
int linux_br_fdb_del(int sock, const char *br_name, const u8* mac);
#endif
int linux_ioctl_socket();
void linux_ioctl_close(int sock);

#endif /* LINUX_IOCTL_H */
