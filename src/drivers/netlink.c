/*
 * Netlink helper functions for driver wrappers
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "netlink.h"
#include <assert.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/route/link.h>

struct netlink_data {
	struct netlink_config *cfg;
	struct netlink_data *next;
};

static struct nl_sock *netlink_global_nl = NULL;
static int netlink_global_sock = -1;
struct netlink_data *netlink_global_head = NULL;

static void netlink_receive_link(struct netlink_data *netlink,
				 void (*cb)(void *ctx, struct ifinfomsg *ifi,
					    u8 *buf, size_t len),
				 struct nlmsghdr *h)
{
	if (cb == NULL || NLMSG_PAYLOAD(h, 0) < sizeof(struct ifinfomsg))
		return;
	cb(netlink->cfg->ctx, NLMSG_DATA(h),
	   (u8 *) NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct ifinfomsg)),
	   NLMSG_PAYLOAD(h, sizeof(struct ifinfomsg)));
}


static void netlink_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct netlink_data *netlink;
	char buf[8192];
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	int max_events = 10;

try_again:
	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			wpa_printf(MSG_INFO, "netlink: recvfrom failed: %s",
				   strerror(errno));
		return;
	}

	h = (struct nlmsghdr *) buf;
	while (NLMSG_OK(h, left)) {
		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			for (netlink = netlink_global_head; netlink; netlink = netlink->next)
				netlink_receive_link(netlink, netlink->cfg->newlink_cb,
						     h);
			break;
		case RTM_DELLINK:
			for (netlink = netlink_global_head; netlink; netlink = netlink->next)
				netlink_receive_link(netlink, netlink->cfg->dellink_cb,
						     h);
			break;
		}

		h = NLMSG_NEXT(h, left);
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "netlink: %d extra bytes in the end of "
			   "netlink message", left);
	}

	if (--max_events > 0) {
		/*
		 * Try to receive all events in one eloop call in order to
		 * limit race condition on cases where AssocInfo event, Assoc
		 * event, and EAPOL frames are received more or less at the
		 * same time. We want to process the event messages first
		 * before starting EAPOL processing.
		 */
		goto try_again;
	}
}


struct netlink_data * netlink_init(struct netlink_config *cfg)
{
	struct netlink_data *netlink;

	netlink = os_zalloc(sizeof(*netlink));
	if (netlink == NULL)
		return NULL;

	netlink->cfg = cfg;

	/* add to linked list */
	netlink->next = netlink_global_head;
	netlink_global_head = netlink;

	/* only open socket if required */
	if (netlink_global_sock >= 0)
		return netlink;

	netlink_global_nl = nl_socket_alloc();
	if (!netlink_global_nl) {
		wpa_printf(MSG_ERROR, "wired-ng:initsocket: failed to alloc netlink socket");
		return NULL;
	}

	nl_socket_disable_seq_check(netlink_global_nl);

	if (nl_connect(netlink_global_nl, NETLINK_ROUTE) < 0) {
		wpa_printf(MSG_ERROR, "wired-ng:initsocket: failed to connect to netlink");
		return NULL;
	}

	nl_socket_add_membership(netlink_global_nl, RTNLGRP_LINK);

	nl_socket_set_nonblocking(netlink_global_nl);
	netlink_global_sock = nl_socket_get_fd(netlink_global_nl);

	eloop_register_read_sock(netlink_global_sock, netlink_receive, NULL, NULL);

	return netlink;
}


void netlink_deinit(struct netlink_data *netlink)
{
	struct netlink_data *i, *prev = NULL;
	if (netlink == NULL)
		return;

	for (i = netlink_global_head; i; i = i->next) {
		if (i == netlink) {
			if (prev) {
				prev->next = i->next;
			} else {
				netlink_global_head = i->next;
			}
			os_free(netlink->cfg);
			os_free(netlink);
			netlink = NULL;
			break;
		}
		prev = i;
	}
	if (!i && netlink) {
		wpa_printf(MSG_ERROR, "netlink: Failed to find netlink "
			   "pointer: %p", netlink);
		os_free(netlink->cfg);
		os_free(netlink);
		netlink = NULL;
	}
	if (!netlink_global_head && netlink_global_sock >= 0) {
		eloop_unregister_read_sock(netlink_global_sock);
		nl_socket_free(netlink_global_nl);
		netlink_global_nl = NULL;
		netlink_global_sock = -1;
	}
}


static const char * linkmode_str(int mode)
{
	switch (mode) {
	case -1:
		return "no change";
	case 0:
		return "kernel-control";
	case 1:
		return "userspace-control";
	}
	return "?";
}


static const char * operstate_str(int state)
{
	switch (state) {
	case -1:
		return "no change";
	case IF_OPER_DORMANT:
		return "IF_OPER_DORMANT";
	case IF_OPER_UP:
		return "IF_OPER_UP";
	}
	return "?";
}


int netlink_send_oper_ifla(struct netlink_data *netlink, int ifindex,
			   int linkmode, int operstate)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifinfo;
		char opts[16];
	} req;
	struct rtattr *rta;
	static int nl_seq;
	ssize_t ret;

	assert(netlink_global_sock >= 0);

	os_memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.hdr.nlmsg_type = RTM_SETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST;
	req.hdr.nlmsg_seq = ++nl_seq;
	req.hdr.nlmsg_pid = 0;

	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_type = 0;
	req.ifinfo.ifi_index = ifindex;
	req.ifinfo.ifi_flags = 0;
	req.ifinfo.ifi_change = 0;

	if (linkmode != -1) {
		rta = aliasing_hide_typecast(
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len)),
			struct rtattr);
		rta->rta_type = IFLA_LINKMODE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = linkmode;
		req.hdr.nlmsg_len += RTA_SPACE(sizeof(char));
	}
	if (operstate != -1) {
		rta = aliasing_hide_typecast(
			((char *) &req + NLMSG_ALIGN(req.hdr.nlmsg_len)),
			struct rtattr);
		rta->rta_type = IFLA_OPERSTATE;
		rta->rta_len = RTA_LENGTH(sizeof(char));
		*((char *) RTA_DATA(rta)) = operstate;
		req.hdr.nlmsg_len += RTA_SPACE(sizeof(char));
	}

	wpa_printf(MSG_DEBUG, "netlink: Operstate: ifindex=%d linkmode=%d (%s), operstate=%d (%s)",
		   ifindex, linkmode, linkmode_str(linkmode),
		   operstate, operstate_str(operstate));

	ret = send(netlink_global_sock, &req, req.hdr.nlmsg_len, 0);
	if (ret < 0) {
		wpa_printf(MSG_DEBUG, "netlink: Sending operstate IFLA "
			   "failed: %s (assume operstate is not supported)",
			   strerror(errno));
	}

	return ret < 0 ? -1 : 0;
}
