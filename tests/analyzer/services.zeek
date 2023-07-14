# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_services.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet_discovery.log
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
# @TEST-EXEC: btest-diff bacnet_device_control.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff files.log
#
# @TEST-DOC: Test BACnet analyzer with trace that contains more services and atomic read/write files.

@load icsnpp/bacnet
