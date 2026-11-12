# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_same_timestamp_orderings.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Test the same-capture-timestamp hazard in the orderings the two frame case does not
# @TEST-DOC: reach. Frames are grouped by timestamp; the frames within a group share one timestamp
# @TEST-DOC: to the microsecond and no two groups share one.
# @TEST-DOC:   1-2    unrouted then routed. The routed packet's own SNET/SLEN/SADR must still be
# @TEST-DOC:          reported, so that scoping state per packet does not simply discard it.
# @TEST-DOC:   3-4    routed request, unrouted response. Routing state must not cross directions.
# @TEST-DOC:   5-6    source specifier then destination specifier. The second packet must replace
# @TEST-DOC:          the state rather than add to it: it reports DNET/DLEN/DADR of its own and no
# @TEST-DOC:          SNET/SLEN/SADR at all.
# @TEST-DOC:   7-9    one routed packet then two unrouted. Neither of the two may report routing.
# @TEST-DOC:   10-11  a BVLC Forwarded-NPDU then a plain frame from the same BBMD. fwd_ip and
# @TEST-DOC:          fwd_port must not carry forward.
# @TEST-DOC:   12-13  a BVLC Forwarded-NPDU then an NPDU-routed frame. The NPDU and BVLC routing
# @TEST-DOC:          dimensions must not mix: frame 13 reports its own SNET/SLEN/SADR and no
# @TEST-DOC:          forwarder.

@load icsnpp/bacnet
