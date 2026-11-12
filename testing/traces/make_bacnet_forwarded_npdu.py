#!/usr/bin/env python3
"""
Build a small synthetic pcap exercising the BVLC Forwarded-NPDU path (BVLC function 0x04).

No upstream ICSNPP test trace contains a Forwarded-NPDU or any BBMD traffic, so the
bacnet_forwarded_npdu half of the patch has nothing to run against without this file.

Frames, all UDP/47808, Ethernet II, IPv4:

  1  192.168.1.5   -> 192.168.1.255  Forwarded-NPDU, originator 192.168.1.77:47808,
                                     NPDU with DNET=65535/DLEN=0 and SNET=3/SLEN=1/SADR=0x6c,
                                     APDU = I-Am for device 108
  2  192.168.1.5   -> 192.168.1.20   Forwarded-NPDU, originator 192.168.1.90:47808,
                                     NPDU with DNET=3/DLEN=1/DADR=0x6c,
                                     APDU = WriteProperty analog-output 5 present-value 72.0
                                            at priority 8
  3  192.168.1.20  -> 192.168.1.5    Forwarded-NPDU, originator 192.168.1.91:47808,
                                     NPDU with SNET=3/SLEN=1/SADR=0x6c,
                                     APDU = SimpleACK for the WriteProperty above
  4  192.168.1.5   -> 192.168.1.20   Forwarded-NPDU, originator 192.168.1.90:47808,
                                     NPDU with NO source and NO destination specifier,
                                     APDU = I-Am for device 108
  5  192.168.1.5   -> 192.168.1.20   Original-Unicast-NPDU, no forwarding and no routing at all,
                                     APDU = ReadProperty analog-output 5 present-value

Frame 5 is the leakage control: it shares a connection and a direction with frame 4, so if the
per-packet routing scratch state ever outlived its packet, frame 5 would inherit frame 4's fwd_ip.
Every new column must be unset on frame 5.
"""

import binascii
import socket
import struct
import sys

LINKTYPE_ETHERNET = 1
MAC_BBMD = "005056000105"
MAC_PEER = "005056000114"


def h(s):
    """Hex string, whitespace allowed, to bytes."""
    return binascii.unhexlify("".join(s.split()))


def ipv4_checksum(hdr):
    total = 0
    for i in range(0, len(hdr), 2):
        total += (hdr[i] << 8) + hdr[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def frame(src_mac, dst_mac, src_ip, dst_ip, payload, src_port=47808, dst_port=47808):
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, 20 + udp_len, 0x1234, 0x0000, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]

    eth = h(dst_mac) + h(src_mac) + h("0800")
    return eth + ip + udp


def bvlc(function, body):
    """Prepend the 4 byte BVLC header. length covers the whole BVLL message."""
    return struct.pack("!BBH", 0x81, function, 4 + len(body)) + body


# --- APDUs -------------------------------------------------------------------------------------
# I-Am: unconfirmed request (0x10), service choice 0 (i-am),
#   object identifier tag 0xC4 -> device (type 8) instance 108 -> (8<<22)|108 = 0x0200006c
#   max APDU 480, segmentation 3 (no segmentation), vendor id 99
APDU_I_AM = h("10 00 C4 0200006C 22 01E0 91 03 21 63")

# WriteProperty: confirmed request, invoke id 0x2a, service choice 0x0f,
#   ctx 0 object identifier analog-output (type 1) instance 5 -> (1<<22)|5 = 0x00400005
#   ctx 1 property identifier 85 (present-value)
#   ctx 3 opening/closing around application tag Real 72.0 (0x42900000)
#   ctx 4 priority 8
APDU_WRITE_PROPERTY = h("00 05 2A 0F 0C 00400005 19 55 3E 44 42900000 3F 49 08")

# SimpleACK for invoke id 0x2a, service choice 0x0f
APDU_SIMPLE_ACK = h("20 2A 0F")

# ReadProperty: confirmed request, invoke id 0x2b, service choice 0x0c,
#   ctx 0 object identifier analog-output instance 5, ctx 1 property 85
APDU_READ_PROPERTY = h("00 05 2B 0C 0C 00400005 19 55")

# --- NPDUs -------------------------------------------------------------------------------------
# version 0x01, then the NPCI control byte, then the specifiers it advertises.
# control 0x28 = network priority normal, destination specifier (0x20) + source specifier (0x08)
NPDU_DEST_BCAST_AND_SRC = h("01 28 FFFF 00 0003 01 6C FF")
# control 0x24 = destination specifier (0x20) + expecting reply (0x04)
NPDU_DEST_ONLY = h("01 24 0003 01 6C FF")
# control 0x08 = source specifier only, no hop count because there is no destination specifier
NPDU_SRC_ONLY = h("01 08 0003 01 6C")
# control 0x00 = no routing information at all
NPDU_PLAIN = h("01 00")
# control 0x04 = expecting reply, no routing information
NPDU_PLAIN_REPLY = h("01 04")


def forwarded(orig_ip, orig_port, rest):
    return bvlc(0x04, socket.inet_aton(orig_ip) + struct.pack("!H", orig_port) + rest)


PACKETS = [
    frame(MAC_BBMD, "ffffffffffff", "192.168.1.5", "192.168.1.255",
          forwarded("192.168.1.77", 47808, NPDU_DEST_BCAST_AND_SRC + APDU_I_AM)),
    frame(MAC_BBMD, MAC_PEER, "192.168.1.5", "192.168.1.20",
          forwarded("192.168.1.90", 47808, NPDU_DEST_ONLY + APDU_WRITE_PROPERTY)),
    frame(MAC_PEER, MAC_BBMD, "192.168.1.20", "192.168.1.5",
          forwarded("192.168.1.91", 47808, NPDU_SRC_ONLY + APDU_SIMPLE_ACK)),
    frame(MAC_BBMD, MAC_PEER, "192.168.1.5", "192.168.1.20",
          forwarded("192.168.1.90", 47808, NPDU_PLAIN + APDU_I_AM)),
    frame(MAC_BBMD, MAC_PEER, "192.168.1.5", "192.168.1.20",
          bvlc(0x0A, NPDU_PLAIN_REPLY + APDU_READ_PROPERTY)),
]


def main(path):
    with open(path, "wb") as fh:
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for i, pkt in enumerate(PACKETS):
            fh.write(struct.pack("!IIII", 1700000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)
    print("wrote %s, %d packets" % (path, len(PACKETS)))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "bacnet_forwarded_npdu.pcap")
