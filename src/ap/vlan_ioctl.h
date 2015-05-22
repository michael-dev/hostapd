/*
 * hostapd / VLAN initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef VLAN_IOCTL_H
#define VLAN_IOCTL_H

int vlan_rem(const char *if_name);
int vlan_add(const char *if_name, int vid, const char *vlan_if_name);
int vlan_set_name_type(unsigned int name_type);

#endif /* VLAN_IOCTL_H */
