#ifndef VLAN_H
#define VLAN_H

struct vlan_description {
	int notempty; /* 0 : no vlan information present, 1: else */
	int untagged; /* >0 802.1q vid */
};

#endif
