# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_error_reject_abort.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet_discovery.log
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Test BACnet analyzer with small trace.

@load icsnpp/bacnet
