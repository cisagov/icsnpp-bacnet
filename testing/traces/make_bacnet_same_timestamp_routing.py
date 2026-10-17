#!/usr/bin/env python3
"""
Build the synthetic pcaps for the same-capture-timestamp routing regression tests.

Two BACnet packets on one connection and in one direction can legitimately carry the same
capture timestamp, so a timestamp is not a packet identity and per-packet state must not be
scoped by one. No upstream ICSNPP test trace contains such a pair, so the property has nothing
to run against without these files.

Written with the standard library only, and with every byte spelled out, so the traces can be
regenerated and audited without a capture tool or a packet-crafting dependency.

  bacnet_same_timestamp_routing.pcap
      The minimal case. Two frames, one connection, one direction, one timestamp to the
      microsecond. Frame 1 carries an NPDU source specifier, frame 2 carries no routing
      information of any kind, so every routing column of every record written for frame 2 must
      be unset.

        ts                    src -> dst                  BACnet
        1756900000.123456     192.0.2.10 -> 192.0.2.20    NPDU SNET=3/SLEN=1/SADR=0x6c,
                                                          WriteProperty invoke 40, priority 10
        1756900000.123456     192.0.2.10 -> 192.0.2.20    NPDU with no specifiers,
                                                          WriteProperty invoke 41, priority 5

  bacnet_same_timestamp_orderings.pcap
      The same hazard in the orderings the minimal case does not reach. Every group shares one
      timestamp within itself and differs from every other group.

        group  ts                  frames  what it pins down
        1      ...000.123456       2       unrouted first, routed second: the routed packet's
                                           own columns must still be filled in
        2      ...001.123456       2       routed request, unrouted response: state must not
                                           cross directions
        3      ...002.123456       2       source specifier then destination specifier: the
                                           second packet must not merge with the first, it must
                                           replace it
        4      ...003.123456       3       one routed packet then two unrouted: contamination
                                           must not run to the end of the group
        5      ...004.123456       2       Forwarded-NPDU then a plain frame from the same BBMD:
                                           fwd_ip/fwd_port must not carry forward
        6      ...005.123456       2       Forwarded-NPDU then an NPDU-routed frame: the two
                                           routing dimensions must not mix
"""

import binascii
import os
import socket
import struct
import sys

LINKTYPE_ETHERNET = 1

MAC = {
    "192.0.2.10": "005056000a0a",
    "192.0.2.20": "005056001414",
    "198.51.100.1": "005056006401",
}

BACNET_PORT = 47808


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


def frame(src_ip, dst_ip, payload, ip_id):
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", BACNET_PORT, BACNET_PORT, udp_len, 0) + payload

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, 20 + udp_len, ip_id, 0x0000, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]

    eth = h(MAC[dst_ip]) + h(MAC[src_ip]) + h("0800")
    return eth + ip + udp


def bvlc(function, body):
    """Prepend the 4 byte BVLC header. length covers the whole BVLL message."""
    return struct.pack("!BBH", 0x81, function, 4 + len(body)) + body


def original_unicast(body):
    return bvlc(0x0A, body)


def forwarded(orig_ip, body, orig_port=BACNET_PORT):
    return bvlc(0x04, socket.inet_aton(orig_ip) + struct.pack("!H", orig_port) + body)


# --- NPDUs -------------------------------------------------------------------------------------
# version 0x01, then the NPCI control byte, then the specifiers that byte advertises.
# 0x08 source specifier, 0x20 destination specifier (which also brings a hop count byte),
# 0x04 expecting reply.
NPDU_NONE = h("01 04")                          # expecting reply, no routing information at all
NPDU_NONE_ACK = h("01 00")                      # no routing information, not expecting a reply
NPDU_SRC = h("01 0C 0003 01 6C")                # SNET=3 SLEN=1 SADR=0x6c
NPDU_DST = h("01 24 0009 01 2A FF")             # DNET=9 DLEN=1 DADR=0x2a, hop count 255


# --- APDUs -------------------------------------------------------------------------------------
def write_property(invoke_id, priority, instance=101, real=0x42480000):
    """Confirmed WriteProperty of analog-output <instance> present-value, at <priority>.

    00      confirmed request, no segmentation      05      max segments / max APDU
    <inv>   invoke id                               0F      service choice 15, writeProperty
    0C ..   context tag 0, object identifier analog-output (type 1) instance <instance>
    19 55   context tag 1, property identifier 85 (present-value)
    3E      opening tag 3   44 ..  application tag 4 (Real), 4 bytes   3F  closing tag 3
    49 ..   context tag 4, priority
    """
    obj = (1 << 22) | instance
    return (h("00 05") + bytes([invoke_id]) + h("0F") +
            h("0C") + struct.pack("!I", obj) +
            h("19 55") +
            h("3E 44") + struct.pack("!I", real) + h("3F") +
            h("49") + bytes([priority]))


def simple_ack(invoke_id):
    """SimpleACK for a WriteProperty."""
    return h("20") + bytes([invoke_id]) + h("0F")


# --- traces ------------------------------------------------------------------------------------
WS = "192.0.2.10"       # workstation, the originator side of connection A
CTRL = "192.0.2.20"     # controller, the responder side of both connections
BBMD = "198.51.100.1"   # BBMD, the originator side of connection B
ORIGIN_A = "198.51.100.77"
ORIGIN_B = "198.51.100.78"

T0 = 1756900000
USEC = 123456   # deliberately not zero: the hazard is not an artifact of whole-second timestamps


def wp(src, dst, npdu, invoke_id, priority):
    """One Original-Unicast-NPDU frame carrying a WriteProperty, as (src, dst, payload)."""
    return (src, dst, original_unicast(npdu + write_property(invoke_id, priority)))


MINIMAL = [
    (T0, USEC) + wp(WS, CTRL, NPDU_SRC, 40, 10),
    (T0, USEC) + wp(WS, CTRL, NPDU_NONE, 41, 5),
]

ORDERINGS = [
    # group 1: unrouted first, routed second
    (T0 + 0, USEC) + wp(WS, CTRL, NPDU_NONE, 50, 5),
    (T0 + 0, USEC) + wp(WS, CTRL, NPDU_SRC, 51, 10),

    # group 2: routed request, unrouted response, same timestamp
    (T0 + 1, USEC) + wp(WS, CTRL, NPDU_SRC, 60, 10),
    (T0 + 1, USEC, CTRL, WS, original_unicast(NPDU_NONE_ACK + simple_ack(60))),

    # group 3: source specifier then destination specifier
    (T0 + 2, USEC) + wp(WS, CTRL, NPDU_SRC, 70, 10),
    (T0 + 2, USEC) + wp(WS, CTRL, NPDU_DST, 71, 5),

    # group 4: one routed packet then two unrouted
    (T0 + 3, USEC) + wp(WS, CTRL, NPDU_SRC, 80, 10),
    (T0 + 3, USEC) + wp(WS, CTRL, NPDU_NONE, 81, 5),
    (T0 + 3, USEC) + wp(WS, CTRL, NPDU_NONE, 82, 1),

    # group 5: Forwarded-NPDU then a plain frame from the same BBMD
    (T0 + 4, USEC, BBMD, CTRL,
     forwarded(ORIGIN_A, NPDU_NONE + write_property(90, 10))),
    (T0 + 4, USEC) + wp(BBMD, CTRL, NPDU_NONE, 91, 5),

    # group 6: Forwarded-NPDU then an NPDU-routed frame
    (T0 + 5, USEC, BBMD, CTRL,
     forwarded(ORIGIN_B, NPDU_NONE + write_property(100, 10))),
    (T0 + 5, USEC) + wp(BBMD, CTRL, NPDU_SRC, 101, 5),
]


def write_pcap(path, spec):
    with open(path, "wb") as fh:
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for i, (sec, usec, src, dst, payload) in enumerate(spec):
            pkt = frame(src, dst, payload, 2000 + i)
            fh.write(struct.pack("!IIII", sec, usec, len(pkt), len(pkt)))
            fh.write(pkt)
    print("wrote %s, %d packets" % (path, len(spec)))


def main(outdir):
    write_pcap(os.path.join(outdir, "bacnet_same_timestamp_routing.pcap"), MINIMAL)
    write_pcap(os.path.join(outdir, "bacnet_same_timestamp_orderings.pcap"), ORDERINGS)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
