# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_forwarded_npdu.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
# @TEST-EXEC: btest-diff bacnet_discovery.log
#
# @TEST-DOC: Test that a BVLC Forwarded-NPDU exposes the B/IP address of the originating device
# @TEST-DOC: and that NPDU source and destination specifiers expose SNET/SLEN/SADR and
# @TEST-DOC: DNET/DLEN/DADR. The last frame of the trace shares a connection and a direction with
# @TEST-DOC: a forwarded frame but carries no routing information of its own, so it also checks
# @TEST-DOC: that the per-packet routing state does not leak into the following packet.

@load icsnpp/bacnet
