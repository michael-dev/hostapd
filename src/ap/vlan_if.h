#ifndef VLAN_IF_H
#define VLAN_IF_H

int vlan_if_nametoindex(char *ifname);
char* vlan_if_indextoname(int idx);

#endif
