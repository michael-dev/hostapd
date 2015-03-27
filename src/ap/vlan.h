#ifndef VLAN_H
#define VLAN_H

#define MAX_NUM_TAGGED_VLAN 32

struct vlan_description {
	int notempty; /* 0 : no vlan information present, 1: else */
	int untagged; /* >0 802.1q vid */
	int tagged[MAX_NUM_TAGGED_VLAN];
};

#endif
