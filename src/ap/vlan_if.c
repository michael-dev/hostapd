#include "net/if.h"

int vlan_if_nametoindex(char *ifname)
{
	return if_nametoindex(ifname);
}

char* vlan_if_indextoname(int idx)
{
	static char buf[IF_NAMESIZE];
	return if_indextoname(idx, buf);
};
