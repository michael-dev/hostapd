#include "net/if.h"

int vlan_if_nametoindex(char *ifname)
{
	return if_nametoindex(ifname);
}

