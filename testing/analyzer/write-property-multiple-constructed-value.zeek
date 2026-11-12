# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_write_property_multiple_constructed_value.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Verify nested context tags in a WritePropertyMultiple value do not end the property list.

@load icsnpp/bacnet
