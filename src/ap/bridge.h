/*
 * hostapd / bridge initialization
 * Copyright 2003, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright (c) 2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HOSTAPD_BRIDGE_H
#define HOSTAPD_BRIDGE_H
int br_delif(const char *br_name, const char *if_name);
int br_addif(const char *br_name, const char *if_name);
int br_delbr(const char *br_name);
int br_addbr(const char *br_name);
int br_getnumports(const char *br_name);
#endif /* HOSTAPD_BRIDGE_H */

