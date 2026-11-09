# @TEST-EXEC: zeek -C -r ${TRACES}/bacnet_malformed_service_tags.pcap %INPUT > events.log
# @TEST-EXEC: btest-diff events.log
#
# @TEST-DOC: Verify malformed zero-length service tags do not crash or emit events.

@load icsnpp/bacnet

event bacnet_unconfirmed_text_message(c: connection,
                                      is_orig: bool,
                                      object_type: count,
                                      instance_number: count,
                                      message_priority: count,
                                      message: string)
    {
    print fmt("unconfirmed-text %d %s", message_priority, message);
    }

event bacnet_confirmed_text_message(c: connection,
                                    is_orig: bool,
                                    invoke_id: count,
                                    object_type: count,
                                    instance_number: count,
                                    message_priority: count,
                                    message: string)
    {
    print fmt("confirmed-text %d %d %s",
              invoke_id, message_priority, message);
    }

event bacnet_subscribe_cov_property(c: connection,
                                    is_orig: bool,
                                    invoke_id: count,
                                    subscriber_process_id: count,
                                    monitored_identifier_object_type: count,
                                    monitored_identifier_instance_number: count,
                                    lifetime: count,
                                    monitored_property: count,
                                    cov_increment: count)
    {
    print fmt("subscribe-cov-property %d %d %d %d %d %d",
              invoke_id, subscriber_process_id,
              monitored_identifier_instance_number, lifetime,
              monitored_property, cov_increment);
    }
