# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_segmented_data.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet_discovery.log
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Test BACnet analyzer with trace that contains segmented data.

@load icsnpp/bacnet
