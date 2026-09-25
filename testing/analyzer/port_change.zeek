# @TEST-EXEC: zeek -Cr ${TRACES}/bacnet_example_port_change.pcap "Bacnet::bacnet_ports={ 5678/udp }" %INPUT
# @TEST-EXEC: btest-diff bacnet_discovery.log
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Test BACnet analyzer with small trace and port change.

@load icsnpp/bacnet
