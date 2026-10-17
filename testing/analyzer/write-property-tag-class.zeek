# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_write_tag_class.pcap %INPUT
# @TEST-EXEC: btest-diff bacnet.log
# @TEST-EXEC: btest-diff bacnet_property.log
#
# @TEST-DOC: Application-class and context-class BACnet tag numbers are separate namespaces
# @TEST-DOC: (ASHRAE 135 clause 20.2.1.1), so a WriteProperty property value carrying
# @TEST-DOC: application tag 2 (Unsigned) or application tag 4 (Real) must not be read as
# @TEST-DOC: context tag 2 (Property Array Index) or context tag 4 (Priority).
# @TEST-DOC: Frame 1 writes Unsigned 42 with no array index and no priority, frame 2 the same
# @TEST-DOC: with priority 8, frame 3 writes Real 72.5 with array index 5 and no priority, and
# @TEST-DOC: frame 4 writes Enumerated 1 as a control, since application tag 9 has no colliding
# @TEST-DOC: context case.
# @TEST-DOC: Expected array_index: unset, unset, 5, unset. Without the class check the first
# @TEST-DOC: two report 42, the Unsigned property value read as an array index.
# @TEST-DOC: Priority is not a field of bacnet_property.log, so the context tag 4 collision is
# @TEST-DOC: not observable in this baseline; frame 2 is kept so a genuine priority is present
# @TEST-DOC: in the trace and the class check is exercised in both directions.

@load icsnpp/bacnet
