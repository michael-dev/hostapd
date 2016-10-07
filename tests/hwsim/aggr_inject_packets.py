"""
Copyright (c) 2015, Pieter Robyns
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""
Copied from https://github.com/rpp0/aggr-inject, stripped down and merged into a single file by
Michael Braun <michael-dev@fami-braun.de>

Changes:
  * minor adoptions

Dependency for Debian:
  * python-crcmod
  * python-scapy
"""

from scapy.all import sr1, sr, srp1, send, sendp, hexdump, ETH_P_IP
from scapy.layers.inet import Raw, Ether, TCP, IP, ICMP, ARP
from scapy.layers.dot11 import Dot11, LLC, SNAP, RadioTap, Dot11Beacon, Dot11Elt, Dot11ProbeResp
import random
import crcmod
import struct
import time

RSN = "\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00"

AP_WLAN_TYPE_OPEN = 0
AP_WLAN_TYPE_WPA = 1
AP_WLAN_TYPE_WPA2 = 2
AP_WLAN_TYPE_WPA_WPA2 = 3
AP_AUTH_TYPE_OPEN = 0
AP_AUTH_TYPE_SHARED = 1
AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"

DOT11_MTU = 4096

DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2

DOT11_SUBTYPE_DATA = 0x00
DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_AUTH_REQ = 0x0B
DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_REASSOC_REQ = 0x02
DOT11_SUBTYPE_QOS_DATA = 0x28

IFNAMSIZ = 16
IFF_TUN = 0x0001
IFF_TAP = 0x0002  # Should we want to tunnel layer 2...
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

# Configuration
DEFAULT_SOURCE_IP = '10.0.0.2'
DEFAULT_DEST_IP = '10.0.0.1'
DEFAULT_SOURCE_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DEST_MAC = 'ff:ff:ff:ff:ff:ff'
CHANNEL = 1

class Level:
    CRITICAL = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3
    BLOAT = 4

VERBOSITY = Level.INFO

class Color:
    GREY = '\x1b[1;37m'
    GREEN = '\x1b[1;32m'
    BLUE = '\x1b[1;34m'
    YELLOW = '\x1b[1;33m'
    RED = '\x1b[1;31m'
    MAGENTA = '\x1b[1;35m'
    CYAN = '\x1b[1;36m'


def clr(color, text):
    return color + str(text) + '\x1b[0m'

def printd(string, level):
    if VERBOSITY >= level:
        print(string)

def get_frequency(channel):
    if channel == 14:
        freq = 2484
    else:
        freq = 2407 + (channel * 5)

    freq_string = struct.pack("<h", freq)

    return freq_string

# 802.11 MAC CRC
def dot11crc(pkt):
    crc_fun = crcmod.Crc(0b100000100110000010001110110110111, rev=True, initCrc=0x0, xorOut=0xFFFFFFFF)
    crc_fun.update(str(pkt))
    crc = struct.pack('<I', crc_fun.crcValue)
    return crc


# For testing purposes
class GarbagePacket():
    def __init__(self):
        self.data = None

    def set_delimiter_garbage(self):
        self.data = '\x4e' * 1024

    def set_null_garbage(self):
        self.data = '\x00' * 1024

    def __str__(self):
        return str(self.data)

    def dump_to_file(self):
        with open('ampdu.bin', 'w') as f:
            printd(clr(Color.YELLOW, "Dumped garbage packet"), Level.INFO)
            f.write(str(self) * 250)


# Normal 802.11 frame class
class Dot11Packet():
    def __init__(self, recv_mac, trans_mac, dst_mac):
        #self.rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
        self.rt = RadioTap(len=18, present='Flags+Channel+dBm_AntSignal+Antenna',       notdecoded='\x00\x00' + get_frequency(CHANNEL) + '\x80\x40\xe2\x00\x00\x00')
        #self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_DATA, addr1=recv_mac, addr2=trans_mac, addr3=dst_mac, SC=0x3060, FCfield=0x01)
        self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_DATA, addr1=recv_mac, addr2=trans_mac, addr3=dst_mac, SC=0x0000, FCfield=0x01)
        self.data = self.rt / self.dot11hdr
        self.recv_mac = recv_mac
        self.trans_mac = trans_mac
        self.dst_mac = dst_mac

    def __str__(self):
        return str(self.data[RadioTap].payload)  # RadioTap information is only useful while sending (in monitor mode).

    def add_data(self, payload):
        self.data = self.data / payload

    def send(self, ifname):
        return sendp(self.data, iface=ifname, verbose=False)


# 802.11 frame class with support for adding MSDUs to a single MPDU
# According to IEEE 802.11-2012 8.3.2 table 8-19 A-MSDU shall have BSSID in outer frame replacing SA/DA as appropiate
class AMSDUPacket():
    def __init__(self, recv_mac, src_mac, dst_mac, ds=0x01, sc=0x0000):
        #self.rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
        self.rt = RadioTap(len=18, present='Flags+Channel+dBm_AntSignal+Antenna',       notdecoded='\x00\x00' + get_frequency(CHANNEL) + '\x80\x40\xe2\x00\x00\x00')
        self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_QOS_DATA, addr1=recv_mac, addr2=src_mac, addr3=dst_mac, SC=sc, FCfield=ds) / Raw("\x80\x00")
        self.data = self.rt / self.dot11hdr
        self.num_subframes = 0

    def __str__(self):
        return str(self.data[RadioTap].payload)

    def add_msdu(self, src_mac, dst_mac, msdu):
        msdu_len = len(msdu)

        if self.num_subframes > 0:
            padding = "\x00" * (4 - (self.last_total_len % 4))  # Align to 4 octets
            self.data /= padding

        self.data = self.data / Ether(src=src_mac, dst=dst_mac, type=msdu_len) / msdu
        self.last_total_len = msdu_len + 6 + 6 + 2

        self.num_subframes += 1

    def send(self, ifname):
        return sendp(self.data, iface=ifname, verbose=False)


"""
Total Aggregate (A-MPDU) length; the aggregate length is the number of bytes of
the entire aggregate. This length should be computed as:
delimiters = start_delim + pad_delim;
frame_pad = (frame_length % 4) ? (4 - (frame_length % 4)) : 0
agg_length = sum_of_all (frame_length + frame_pad + 4 * delimiters)
"""
# 802.11 frame class with support for adding multiple MPDUs to a single PHY frame
class AMPDUPacket():
    def __init__(self, recv_mac, src_mac, dst_mac, ds=0x01):
        self.rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
        self.dot11hdr = Dot11(type="Data", subtype=DOT11_SUBTYPE_QOS_DATA, addr1=recv_mac, addr2=src_mac, addr3=dst_mac, SC=0x3060, FCfield=ds) / Raw("\x00\x00")
        self.data = self.rt
        self.num_subframes = 0
        self.recv_mac = recv_mac
        self.src_mac = src_mac
        self.dst_mac = dst_mac

    def __str__(self):
        return str(self.data[RadioTap].payload)

    # Higher layer packet
    def add_msdu(self, msdu, msdu_len=-1):
        # Default msdu len
        if msdu_len == -1:
            msdu_len = len(msdu)

        mpdu_len = msdu_len + len(self.dot11hdr) + 4  # msdu + mac80211 + FCS

        if mpdu_len % 4 != 0:
            padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
        else:
            padding = ""
        mpdu_len <<= 4
        crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

        crc = crc_fun(struct.pack('<H', mpdu_len))
        maccrc = dot11crc(str(self.dot11hdr / msdu))
        delim_sig = 0x4E

        #print('a-mpdu: len %d crc %02x delim %02x' % (mpdu_len >> 4, crc, delim_sig))
        #hexdump(maccrc)
        ampdu_header = struct.pack('<HBB', mpdu_len, crc, delim_sig)
        #hexdump(ampdu_header)

        self.data = self.data / ampdu_header / self.dot11hdr / msdu / maccrc / padding

        self.num_subframes += 1

    def add_padding(self, times):  # Add padding delimiter
        for i in range(0, times):
            self.data /= "\x00\x00\x20\x4e"

    def add_padding_bogus(self, times):  # Add bogus padding
        for i in range(0, times):
            self.data /= "\xff\xff\xff\xff"

    def send(self, ifname):
        return sendp(self.data, iface=ifname, verbose=False)

    def dump_to_file(self):
        with open('ampdu.bin', 'w') as f:
            for i in range(0, 1024):
                f.write(str(self))  # Try to shift position so our payload will land on correct offset


# ICMP Echo Request packet
def ping_packet(seq=0, src=DEFAULT_SOURCE_IP, dst=DEFAULT_DEST_IP, length=-1):
    icmp_packet = ICMP(seq=seq, type=8, code=0) / "XXXXXX"
    icmp_packet = ICMP(icmp_packet.do_build())  # Force checksum calculation

    icmp_length = length
    if length == -1:
        icmp_length = len(icmp_packet)

    ping = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
               / SNAP(OUI=0x000000, code=ETH_P_IP) \
               / IP(src=src, dst=dst, len=(20 + icmp_length)) \
               / icmp_packet

    return ping


# ARP packet
def arp_packet(hwsrc, psrc, hwdst, pdst):
    arp_packet = ARP(hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst, op=1)
    arp = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
               / SNAP(OUI=0x000000, code=0x0806) \
               / arp_packet

    return arp


# TCP syn packet
def tcp_syn(src_ip, dst_ip, port):
    tcp_syn_p = TCP(dport=port, flags="S", window=29200, seq=random.randint(0, 100000), sport=random.randint(40000, 60000), options=[('MSS', 1460), ('SAckOK', ''), ('Timestamp', (147229543, 0)), ('NOP', None), ('WScale', 7)])

    syn = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
               / SNAP(OUI=0x000000, code=ETH_P_IP) \
               / IP(src=src_ip, dst=dst_ip, flags=0x02, tos=0x10, len=(20 + len(tcp_syn_p))) \
               / tcp_syn_p
    syn = LLC(str(syn))

    #syn.show()

    return syn


# 802.11 Beacon frame
# TODO: Fix me; duplicate code
def ssid_packet():
    ap_mac = '00:00:00:00:00:00'
    rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
    beacon_packet = Dot11(subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=ap_mac, addr3=ap_mac) \
                 / Dot11Beacon(cap=0x2105)                                                           \
                 / Dot11Elt(ID='SSID', info="injected SSID")                                         \
                 / Dot11Elt(ID='Rates', info=AP_RATES)                                               \
                 / Dot11Elt(ID='DSset', info=chr(CHANNEL))

    # Update sequence number
    beacon_packet.SC = 0x3060

    # Update timestamp
    beacon_packet[Dot11Beacon].timestamp = time.time()

    mpdu_len = len(beacon_packet) + 4

    if mpdu_len % 4 != 0:
        padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
    else:
        padding = ""
    mpdu_len <<= 4
    crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

    crc = crc_fun(struct.pack('<H', mpdu_len))
    maccrc = dot11crc(str(beacon_packet))
    delim_sig = 0x4E

    #print('a-mpdu: len %d crc %02x delim %02x' % (mpdu_len >> 4, crc, delim_sig))
    #hexdump(maccrc)
    ampdu_header = struct.pack('<HBB', mpdu_len, crc, delim_sig)
    #hexdump(ampdu_header)

    data = ampdu_header / beacon_packet / maccrc / padding
    data /= "\x00\x00\x20\x4e" * 8
    data = str(data)

    return data


# 802.11 Probe Response
# TODO: Fix me; duplicate code
def probe_response():
    rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(CHANNEL) + '\xc0\x00\xc0\x01\x00\x00')
    beacon_packet = Dot11(subtype=5, addr1='ff:ff:ff:ff:ff:ff', addr2="be:da:de:ad:be:ef", addr3="be:da:de:ad:be:ef", SC=0x3060) \
                    / Dot11ProbeResp(timestamp=time.time(), beacon_interval=0x0064, cap=0x2104) \
                    / Dot11Elt(ID='SSID', info="injected SSID") \
                    / Dot11Elt(ID='Rates', info=AP_RATES) \
                    / Dot11Elt(ID='DSset', info=chr(1))

    # Update sequence number
    beacon_packet.SC = 0x3060

    mpdu_len = len(beacon_packet) + 4

    if mpdu_len % 4 != 0:
        padding = "\x00" * (4 - (mpdu_len % 4))  # Align to 4 octets
    else:
        padding = ""
    mpdu_len <<= 4
    crc_fun = crcmod.mkCrcFun(0b100000111, rev=True, initCrc=0x00, xorOut=0xFF)

    crc = crc_fun(struct.pack('<H', mpdu_len))
    maccrc = dot11crc(str(beacon_packet))
    delim_sig = 0x4E

    #print('a-mpdu: len %d crc %02x delim %02x' % (mpdu_len >> 4, crc, delim_sig))
    #hexdump(maccrc)
    ampdu_header = struct.pack('<HBB', mpdu_len, crc, delim_sig)
    #hexdump(ampdu_header)

    data = ampdu_header / beacon_packet / maccrc / padding
    data /= "\x00\x00\x20\x4e" * 8
    data = str(data)

    return data
