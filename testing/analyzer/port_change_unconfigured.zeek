# @TEST-EXEC: zeek -Cr ${TRACES}/bacnet_example_port_change.pcap %INPUT
# @TEST-EXEC: test ! -e bacnet.log
# @TEST-EXEC: test ! -e bacnet_discovery.log
# @TEST-EXEC: test ! -e bacnet_property.log
#
# @TEST-DOC: Confirm a non-standard UDP port is not parsed before port registration when DPD is disabled.

@load icsnpp/bacnet/main
@load icsnpp/bacnet/files
