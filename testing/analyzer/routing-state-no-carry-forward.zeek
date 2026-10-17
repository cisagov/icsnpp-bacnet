# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_same_timestamp_routing.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Test that per-packet routing state never outlives the packet that set it, when the
# @TEST-DOC: packet after it carries the same capture timestamp. The trace holds two frames on one
# @TEST-DOC: connection and in one direction, with timestamps that are identical to the
# @TEST-DOC: microsecond. Frame 1 carries an NPDU source specifier, frame 2 carries no routing
# @TEST-DOC: information of any kind, so every routing column of both records written for frame 2
# @TEST-DOC: has to be unset. A capture timestamp is not a packet identity; scoping the state by
# @TEST-DOC: timestamp made frame 2 report frame 1's SNET/SLEN/SADR as its own.

@load icsnpp/bacnet
