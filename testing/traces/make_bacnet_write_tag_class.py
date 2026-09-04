#!/usr/bin/env python3
"""
Generate testing/traces/bacnet_write_tag_class.pcap.

Committed so the trace is auditable and reproducible rather than an opaque binary.
Requires scapy for Ethernet/IP/UDP framing only; every BACnet byte is built here.

The trace exercises the boundary between BACnet's two tag-number namespaces.
Application-class and context-class tag numbers are independent (ASHRAE 135 clause
20.2.1.1), so in a WriteProperty-Request:

    application tag 2 (Unsigned) collides with context tag 2 (Property Array Index)
    application tag 4 (Real)     collides with context tag 4 (Priority)

The property value sits between the opening and closing context tag 3 and carries an
application tag, so a dispatch loop that keys on the tag number alone reads the value
as a parameter. Four frames, all analog-output 101 present-value:

  1. Unsigned 42, no array index, no priority  -> array_index unset, priority unset
  2. Unsigned 42, no array index, priority 8   -> array_index unset, priority 8
  3. Real 72.5, array index 5, no priority     -> array_index 5,     priority unset
     (72.5 encodes as 42 91 00 00; without the class check its leading byte 0x42
     is reported as priority 66.  The value is 72.5 rather than a round number
     because testing/scripts/diff-remove-timestamps rewrites the literal string
     "0.000000" anywhere on a line, which would obscure the value column.)
  4. Enumerated 1, no array index, no priority -> control: application tag 9 has no
                                                  colliding context case, so nothing
                                                  should change about how it is read

Addresses are from RFC 5737 documentation space so the trace can never be mistaken
for a real capture.

Usage:  python3 make_bacnet_write_tag_class.py
"""
import os
import struct

from scapy.all import Ether, IP, UDP, Raw, wrpcap

SRC = "192.0.2.10"
DST = "192.0.2.20"
SRC_MAC = "02:00:00:00:00:0a"
DST_MAC = "02:00:00:00:00:14"
BACNET_PORT = 47808
BASE_TIME = 1756900000  # fixed epoch so the pcap regenerates byte-identically

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "bacnet_write_tag_class.pcap")


def minimal_unsigned(value):
    if value == 0:
        return b"\x00"
    out = b""
    while value:
        out = bytes([value & 0xFF]) + out
        value >>= 8
    return out


def context_tag(number, data):
    if number > 14:
        raise ValueError("extended context tag numbers are not needed here")
    length = len(data)
    if length > 4:
        raise ValueError("extended lengths are not needed here")
    return bytes([(number << 4) | 0x08 | length]) + data


def opening_tag(number):
    return bytes([(number << 4) | 0x0E])


def closing_tag(number):
    return bytes([(number << 4) | 0x0F])


def app_real(value):
    return b"\x44" + struct.pack(">f", value)


def app_unsigned(value):
    data = minimal_unsigned(value)
    return bytes([0x20 | len(data)]) + data


def app_enumerated(value):
    data = minimal_unsigned(value)
    return bytes([0x90 | len(data)]) + data


def object_identifier(obj_type, instance):
    return struct.pack(">I", ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF))


def write_property(invoke_id, value_bytes, array_index=None, priority=None):
    # Confirmed-Request, segmented-response-accepted, max APDU 1024,
    # service choice 15 (writeProperty)
    apdu = bytes([0x02, 0x03, invoke_id, 0x0F])
    apdu += context_tag(0, object_identifier(1, 101))     # analog-output 101
    apdu += context_tag(1, minimal_unsigned(85))          # present-value
    if array_index is not None:
        apdu += context_tag(2, minimal_unsigned(array_index))
    apdu += opening_tag(3) + value_bytes + closing_tag(3)
    if priority is not None:
        apdu += context_tag(4, bytes([priority]))
    return apdu


def npdu(apdu):
    # version 1, control 0x04 (expecting reply, no routing specifiers)
    return bytes([0x01, 0x04]) + apdu


def bvlc_original_unicast(payload):
    return struct.pack(">BBH", 0x81, 0x0A, 4 + len(payload)) + payload


FRAMES = [
    write_property(30, app_unsigned(42)),
    write_property(31, app_unsigned(42), priority=8),
    write_property(32, app_real(72.5), array_index=5),
    write_property(33, app_enumerated(1)),
]


def main():
    pkts = []
    for idx, apdu in enumerate(FRAMES):
        payload = bvlc_original_unicast(npdu(apdu))
        pkt = (Ether(src=SRC_MAC, dst=DST_MAC)
               / IP(src=SRC, dst=DST, id=1000 + idx, ttl=64, flags=0)
               / UDP(sport=BACNET_PORT, dport=BACNET_PORT)
               / Raw(load=payload))
        pkt.time = BASE_TIME + idx
        pkts.append(pkt)
    wrpcap(OUT, pkts)
    print("wrote %s (%d frames)" % (OUT, len(pkts)))


if __name__ == "__main__":
    main()
