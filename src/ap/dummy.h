#ifndef HOSTAPD_DUMMY_H
#define HOSTAPD_DUMMY_H

#ifdef CONFIG_LIBNL3_ROUTE
int dummy_add(const char* if_name, const u8* addr);
int dummy_del(const char *if_name);
#endif /* CONFIG_LIBNL3_ROUTE */

#endif

