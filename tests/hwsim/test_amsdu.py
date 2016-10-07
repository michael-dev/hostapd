#!/usr/bin/python
#
# Test cases for AP VLAN
# Copyright (c) 2013-2014, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
import time
import subprocess
import logging
import hwsim_utils
import hostapd
import os
import os.path
from utils import HwsimSkip
from tshark import run_tshark

logger = logging.getLogger(__name__)

try:
    from aggr_inject_packets import AMSDUPacket, ping_packet, Dot11Packet
    aggr_imported = True
except ImportError:
    aggr_imported = False

def test_ap_accept_amsdu_source_spoofing(dev, apdev, p):
    """sta sending A-MSDU with spoofed inner source address"""

    if (not aggr_imported):
        raise HwsimSkip("amsdu injection not supported / missing crcmod or scapy?")
        return

    tsharkp = None

    try:
        hapd = hostapd.add_ap(apdev[0], { "ssid": "open" })

        dev[0].connect("open", key_mgmt="NONE", scan_freq="2412",
                       bg_scan_period="0")
        ev = hapd.wait_event([ "AP-STA-CONNECTED" ], timeout=5)
        if ev is None:
            raise Exception("No connection event received from hostapd")

        # capture
	if os.path.isfile("/tmp/amsdu.pcap"):
             os.remove("/tmp/amsdu.pcap")
        tsharkp = subprocess.Popen(["/usr/bin/tshark","-i",apdev[0]['ifname'],"-w","/tmp/amsdu.pcap"], close_fds=True, shell=False)

        # inject some traffic
        subprocess.call(['iw', 'dev', dev[0].ifname, 'interface', 'add', 'amsdu0', 'type', 'monitor'])
        subprocess.call(['ip', 'link', 'set', 'dev', 'amsdu0', 'up'])

        logger.info("waiting for tshark to start up")
        time.sleep(3)
        logger.info("injecting frames")

        # no A-MSDU
        bssid = hapd.own_addr()
        outer_sa = dev[0].own_addr()
        faked_sa = "00:ff:ff:ff:ff:ff"

	for i in range(4):
            msdu_pkt = Dot11Packet(bssid, outer_sa, "00:ff:ff:ff:ff:00")
            msdu_pkt.add_data(ping_packet(0, "10.0.0.0", "192.168.0.0"))
            msdu_pkt.send("amsdu0")
            time.sleep(1)

        # 1. faked packet
	for i in range(4):
            amsdu_pkt = AMSDUPacket(bssid, outer_sa, bssid,0x01,0x3080)
            amsdu_pkt.add_msdu(faked_sa, "00:ff:ff:ff:ff:02", ping_packet(2, "10.0.0.2", "192.168.0.2"))
            amsdu_pkt.send("amsdu0")
            time.sleep(1)

        # 2. correct packet
	for i in range(4):
            amsdu_pkt = AMSDUPacket(bssid, outer_sa, bssid,0x01,0x3090)
            amsdu_pkt.add_msdu(outer_sa, "00:ff:ff:ff:ff:01", ping_packet(1, "10.0.0.1", "192.168.0.1"))
            amsdu_pkt.send("amsdu0")
            time.sleep(1)

        # let the AP send couple of Beacon frames
        logger.info("packets injected, waiting for them to be received")
        time.sleep(1)
        tsharkp.terminate()
        time.sleep(2)

        out = run_tshark(os.path.join(p['logdir'], "/tmp/amsdu.pcap"),
                         "eth.src == " + outer_sa + " and eth.dst == 00:ff:ff:ff:ff:00");
        if (out is None) or (len(out.splitlines()) < 1):
            raise Exception("MSDU not received -- packet injection of MSDU failed")
        logger.info("MSDU injection ok")

        out = run_tshark(os.path.join(p['logdir'], "/tmp/amsdu.pcap"),
                         "eth.src == " + outer_sa + " and eth.dst == 00:ff:ff:ff:ff:01");
        if (out is None) or (len(out.splitlines()) < 1):
            raise Exception("A-MSDU not received -- packet injection of A-MSDU failed")
        logger.info("A-MSDU injection ok")

        out = run_tshark(os.path.join(p['logdir'], "/tmp/amsdu.pcap"),
                         "eth.src == " + faked_sa + " and eth.dst == 00:ff:ff:ff:ff:02");
        if out is not None:
            lines = out.splitlines()
            if len(lines) > 0:
                logger.error("A-MSDU injection with spoofed source was received")
                raise Exception("A-MSDU decoded into packet with faked source")
        logger.info("A-MSDU injection with spoofed source was not received")

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()

    finally:
        if tsharkp:
            tsharkp.terminate()
            tsharkp.kill()
        subprocess.call(['ip', 'link', 'set', 'dev', 'amsdu0', 'down'])
        subprocess.call(['ip', 'link', 'del', 'amsdu0'])
	if os.path.isfile("/tmp/amsdu.pcap"):
             os.remove("/tmp/amsdu.pcap")

