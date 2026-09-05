##! main.zeek
##!
##! Binpac BACnet Protocol Analyzer - Contains the base script-layer functionality for processing
##!                                   events emitted from the analyzer.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module Bacnet;

export {
    redef enum Log::ID += { LOG_BACNET,
                            LOG_BACNET_DISCOVERY,
                            LOG_BACNET_PROPERTY,
                            LOG_BACNET_DEVICE_CONTROL};

    ###############################################################################################
    ################################  BACnet_Header -> bacnet.log  ################################
    ###############################################################################################
    type BACnet_Header: record {
        ts                      : time      &log;   ##< Timestamp of event
        uid                     : string    &log;   ##< Zeek unique ID for connection
        id                      : conn_id   &log;   ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &log;   ##< Source IP Address
        source_p                : port      &log;   ##< Source Port
        destination_h           : addr      &log;   ##< Destination IP Address
        destination_p           : port      &log;   ##< Destination Port
        bvlc_function           : string    &log;   ##< BVLC function (see bvlc_functions)
        pdu_type                : string    &log;   ##< APDU type (see apdu_types)
        pdu_service             : string    &log;   ##< APDU service (see unconfirmed_service_choice and confirmed_service_choice)
        invoke_id               : count     &log;   ##< Invoke ID
        result_code             : string    &log;   ##< See (abort_reasons, reject_reasons, and error_codes)
        snet                    : count     &log &optional;   ##< NPDU Source Network Number (routed traffic only)
        slen                    : count     &log &optional;   ##< Length of NPDU Source MAC layer address, 0 means broadcast
        sadr                    : string    &log &optional;   ##< NPDU Source MAC layer address, lowercase hex
        dnet                    : count     &log &optional;   ##< NPDU Destination Network Number (routed traffic only)
        dlen                    : count     &log &optional;   ##< Length of NPDU Destination MAC layer address, 0 means broadcast
        dadr                    : string    &log &optional;   ##< NPDU Destination MAC layer address, lowercase hex
        fwd_ip                  : addr      &log &optional;   ##< B/IP Address of Originating Device (BVLC Forwarded-NPDU only)
        fwd_port                : port      &log &optional;   ##< B/IP Port of Originating Device (BVLC Forwarded-NPDU only)
    };

    global log_bacnet: event(rec: BACnet_Header);

    ###############################################################################################
    ##################  Who-Is, I-Am, Who-Has, & I-Have -> bacnet_discovery.log  ##################
    ###############################################################################################
    type BACnet_Discovery: record {
        ts                      : time      &log;   ##< Timestamp of event
        uid                     : string    &log;   ##< Zeek unique ID for connection
        id                      : conn_id   &log;   ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &log;   ##< Source IP Address
        source_p                : port      &log;   ##< Source Port
        destination_h           : addr      &log;   ##< Destination IP Address
        destination_p           : port      &log;   ##< Destination Port
        pdu_service             : string    &log;   ##< who-is, i-am, who-has, or i-have
        device_id_type          : string    &log;   ##< BACnetObjectIdentifier device (see object_types)
        device_id_number        : count     &log;   ##< BACnetObjectIdentifier device instance number
        object_type             : string    &log;   ##< BACnetObjectIdentifier object (see object_types)
        instance_number         : count     &log;   ##< BACnetObjectIdentifier object instance number
        vendor                  : string    &log;   ##< Vendor Name (i-am and i-have requests)
        range                   : string    &log;   ##< Specify range of devices to return (in who-is and who-has requests)
        object_name             : string    &log;   ##< Object name searching for (who-has) or responding with (i-have)
        snet                    : count     &log &optional;   ##< NPDU Source Network Number (routed traffic only)
        slen                    : count     &log &optional;   ##< Length of NPDU Source MAC layer address, 0 means broadcast
        sadr                    : string    &log &optional;   ##< NPDU Source MAC layer address, lowercase hex
        dnet                    : count     &log &optional;   ##< NPDU Destination Network Number (routed traffic only)
        dlen                    : count     &log &optional;   ##< Length of NPDU Destination MAC layer address, 0 means broadcast
        dadr                    : string    &log &optional;   ##< NPDU Destination MAC layer address, lowercase hex
        fwd_ip                  : addr      &log &optional;   ##< B/IP Address of Originating Device (BVLC Forwarded-NPDU only)
        fwd_port                : port      &log &optional;   ##< B/IP Port of Originating Device (BVLC Forwarded-NPDU only)
    };
    global log_bacnet_discovery: event(rec: BACnet_Discovery);

    ###############################################################################################
    ###################  Read-Property & Write-Property -> bacnet_property.log  ###################
    ###############################################################################################
    type BACnet_Property: record {
        ts                      : time      &log;   ##< Timestamp of event
        uid                     : string    &log;   ##< Zeek unique ID for connection
        id                      : conn_id   &log;   ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &log;   ##< Source IP Address
        source_p                : port      &log;   ##< Source Port
        destination_h           : addr      &log;   ##< Destination IP Address
        destination_p           : port      &log;   ##< Destination Port
        invoke_id               : count     &log;   ##< invoke ID for help matching requests/responses
        pdu_service             : string    &log;   ##< read-property-request/ack, write-property-request
        object_type             : string    &log;   ##< BACnetObjectIdentifier object (see object_types)
        instance_number         : count     &log;   ##< BACnetObjectIdentifier instance number
        property                : string    &log;   ##< Property type (see property_identifiers)
        array_index             : count     &log;   ##< Array index of property
        value                   : string    &log;   ##< Value of property
        snet                    : count     &log &optional;   ##< NPDU Source Network Number (routed traffic only)
        slen                    : count     &log &optional;   ##< Length of NPDU Source MAC layer address, 0 means broadcast
        sadr                    : string    &log &optional;   ##< NPDU Source MAC layer address, lowercase hex
        dnet                    : count     &log &optional;   ##< NPDU Destination Network Number (routed traffic only)
        dlen                    : count     &log &optional;   ##< Length of NPDU Destination MAC layer address, 0 means broadcast
        dadr                    : string    &log &optional;   ##< NPDU Destination MAC layer address, lowercase hex
        fwd_ip                  : addr      &log &optional;   ##< B/IP Address of Originating Device (BVLC Forwarded-NPDU only)
        fwd_port                : port      &log &optional;   ##< B/IP Port of Originating Device (BVLC Forwarded-NPDU only)
        priority                : count     &log &optional;   ##< Write priority 1-16, unset when the request omitted it
    };
    global log_bacnet_property: event(rec: BACnet_Property);

    ###############################################################################################
    #########  Reinitialize-Device & Device-Communication-Control -> bacnet_property.log  #########
    ###############################################################################################
    type BACnet_Device_Control: record {
        ts                      : time      &log;   ##< Timestamp of event
        uid                     : string    &log;   ##< Zeek unique ID for connection
        id                      : conn_id   &log;   ##< Zeek connection struct (addresses and ports)
        is_orig                 : bool      &log;   ##< the message came from the originator/client or the responder/server
        source_h                : addr      &log;   ##< Source IP Address
        source_p                : port      &log;   ##< Source Port
        destination_h           : addr      &log;   ##< Destination IP Address
        destination_p           : port      &log;   ##< Destination Port
        invoke_id               : count     &log;   ##< invoke ID for help matching requests/responses
        pdu_service             : string    &log;   ##< reinitialize_device or device_communication_control
        time_duration           : count     &log;   ##< number of minutes remote device should ignore other APDUs
        device_state            : string    &log;   ##< state to put device into
        password                : string    &log;   ##< password
        result                  : string    &log;   ##< Success, Error, Reject, or Abort
        result_code             : string    &log;   ##< resulting Error/Reject/Abort Code
        snet                    : count     &log &optional;   ##< NPDU Source Network Number (routed traffic only)
        slen                    : count     &log &optional;   ##< Length of NPDU Source MAC layer address, 0 means broadcast
        sadr                    : string    &log &optional;   ##< NPDU Source MAC layer address, lowercase hex
        dnet                    : count     &log &optional;   ##< NPDU Destination Network Number (routed traffic only)
        dlen                    : count     &log &optional;   ##< Length of NPDU Destination MAC layer address, 0 means broadcast
        dadr                    : string    &log &optional;   ##< NPDU Destination MAC layer address, lowercase hex
        fwd_ip                  : addr      &log &optional;   ##< B/IP Address of Originating Device (BVLC Forwarded-NPDU only)
        fwd_port                : port      &log &optional;   ##< B/IP Port of Originating Device (BVLC Forwarded-NPDU only)
    };
    global log_bacnet_device_control: event(rec: BACnet_Device_Control);

    ###############################################################################################
    ###########  Routing information recovered from the NPDU and BVLC layers (not logged)  #########
    ###############################################################################################
    ## Scratch state holding the routing addresses seen on the packet currently being processed.
    ## The BACnet analyzer emits bacnet_npdu_source, bacnet_npdu_destination and
    ## bacnet_forwarded_npdu while parsing the layers that sit above the datalink and below the
    ## APDU, so those events always arrive before the APDU events generated from the same
    ## datagram. The handlers below stash what they see here, and every log record written for
    ## that same packet picks the values back up.
    ##
    ## pdu_seq is what scopes the stash to a single packet. It is the analyzer's own count of
    ## BACnet PDUs on this connection, delivered by bacnet_bvlc_header, which is generated once
    ## per datagram before any of that datagram's contents are parsed. That same event also
    ## empties the stash, so a packet cannot read one that belongs to an earlier packet even by
    ## accident. A capture timestamp cannot do either job: two packets on one connection, in one
    ## direction, can legitimately share one, and the packet that followed a routed one would then
    ## read the routed packet's addresses back out. is_orig is kept alongside pdu_seq as a
    ## direction cross-check.
    type BACnet_Routing: record {
        pdu_seq                 : count;            ##< sequence number of the PDU this came from
        is_orig                 : bool;             ##< direction of the packet this came from
        snet                    : count     &optional;
        slen                    : count     &optional;
        sadr                    : string    &optional;
        dnet                    : count     &optional;
        dlen                    : count     &optional;
        dadr                    : string    &optional;
        fwd_ip                  : addr      &optional;
        fwd_port                : port      &optional;
    };

    ## Log policies, for log filtering.
    global log_policy: Log::PolicyHook;
    global log_policy_discovery: Log::PolicyHook;
    global log_policy_property: Log::PolicyHook;
    global log_policy_device_control: Log::PolicyHook;

}

## Carries the per-packet routing scratch state described above, and the sequence number of the
## BACnet PDU currently being processed on this connection.
redef record connection += {
    bacnet_routing: BACnet_Routing &optional;
    bacnet_pdu_seq: count &optional;
};

## Defines BACnet Ports
const ports = { 47808/udp };
redef likely_server_ports += { ports };

###################################################################################################
#######  Defines Log Streams for bacnet.log, bacnet_discovery.log, and bacnet_property.log  #######
###################################################################################################
event zeek_init() &priority=5{
    Log::create_stream(Bacnet::LOG_BACNET, [$columns=BACnet_Header,
                                            $ev=log_bacnet,
                                            $path="bacnet",
                                            $policy=log_policy]);

    Log::create_stream(Bacnet::LOG_BACNET_DISCOVERY, [$columns=BACnet_Discovery,
                                                      $ev=log_bacnet_discovery,
                                                      $path="bacnet_discovery",
                                                      $policy=log_policy_discovery]);

    Log::create_stream(Bacnet::LOG_BACNET_PROPERTY, [$columns=BACnet_Property,
                                                     $ev=log_bacnet_property,
                                                     $path="bacnet_property",
                                                     $policy=log_policy_property]);

    Log::create_stream(Bacnet::LOG_BACNET_DEVICE_CONTROL, [$columns=BACnet_Device_Control,
                                                     $ev=log_bacnet_device_control,
                                                     $path="bacnet_device_control",
                                                     $policy=log_policy_device_control]);

    Analyzer::register_for_ports(Analyzer::ANALYZER_BACNET, ports);
}

###################################################################################################
#######  Ensure that conn.log:service is set if it has not already been                     #######
###################################################################################################
function set_service(c: connection) {
  if ((!c?$service) || (|c$service| == 0))
    add c$service["bacnet"];
}

###################################################################################################
#####  Routing scratch state helpers - see the BACnet_Routing comment in the export block     #####
###################################################################################################

## Sequence number of the BACnet PDU being processed on this connection, or 0 when the analyzer
## has not reported one. It reports one for every BACnet/IP datagram, from the outermost header,
## so in practice the fallback is only reached if bacnet_bvlc_header is never generated at all.
function current_pdu_seq(c: connection): count
{
    return c?$bacnet_pdu_seq ? c$bacnet_pdu_seq : 0;
}

## Returns the routing scratch state for the packet being processed, creating or resetting it if
## the state on hand belongs to a different packet or a different direction. Resetting rather than
## adding to it matters as much as the guard in has_routing does: a packet carrying only a
## destination specifier must not pick up the source specifier of the packet before it.
function routing_state(c: connection, is_orig: bool): BACnet_Routing
{
    local pdu_seq = current_pdu_seq(c);

    if ( ! c?$bacnet_routing ||
         c$bacnet_routing$pdu_seq != pdu_seq ||
         c$bacnet_routing$is_orig != is_orig )
        c$bacnet_routing = [$pdu_seq=pdu_seq, $is_orig=is_orig];

    return c$bacnet_routing;
}

## True when routing state was recorded for the packet being processed, in this direction. Without
## a sequence number there is no way to tell one packet from another, so the answer is no and the
## routing columns are left unset rather than filled in from whatever was seen last.
function has_routing(c: connection, is_orig: bool): bool
{
    return c?$bacnet_pdu_seq &&
           c?$bacnet_routing &&
           c$bacnet_routing$pdu_seq == c$bacnet_pdu_seq &&
           c$bacnet_routing$is_orig == is_orig;
}

## The four functions below copy that state onto a log record just before it is written. Zeek has
## no record polymorphism, so there is one per log record type. Every assignment is conditional:
## a field the packet did not carry stays unset and logs as the unset placeholder, which is what
## keeps a capture with no routed or forwarded traffic reading exactly as it did before.
function apply_routing_header(c: connection, rec: BACnet_Header)
{
    if ( ! has_routing(c, rec$is_orig) )
        return;

    local routing = c$bacnet_routing;

    if ( routing?$snet )
        rec$snet = routing$snet;
    if ( routing?$slen )
        rec$slen = routing$slen;
    if ( routing?$sadr )
        rec$sadr = routing$sadr;
    if ( routing?$dnet )
        rec$dnet = routing$dnet;
    if ( routing?$dlen )
        rec$dlen = routing$dlen;
    if ( routing?$dadr )
        rec$dadr = routing$dadr;
    if ( routing?$fwd_ip )
        rec$fwd_ip = routing$fwd_ip;
    if ( routing?$fwd_port )
        rec$fwd_port = routing$fwd_port;
}

function apply_routing_discovery(c: connection, rec: BACnet_Discovery)
{
    if ( ! has_routing(c, rec$is_orig) )
        return;

    local routing = c$bacnet_routing;

    if ( routing?$snet )
        rec$snet = routing$snet;
    if ( routing?$slen )
        rec$slen = routing$slen;
    if ( routing?$sadr )
        rec$sadr = routing$sadr;
    if ( routing?$dnet )
        rec$dnet = routing$dnet;
    if ( routing?$dlen )
        rec$dlen = routing$dlen;
    if ( routing?$dadr )
        rec$dadr = routing$dadr;
    if ( routing?$fwd_ip )
        rec$fwd_ip = routing$fwd_ip;
    if ( routing?$fwd_port )
        rec$fwd_port = routing$fwd_port;
}

function apply_routing_property(c: connection, rec: BACnet_Property)
{
    if ( ! has_routing(c, rec$is_orig) )
        return;

    local routing = c$bacnet_routing;

    if ( routing?$snet )
        rec$snet = routing$snet;
    if ( routing?$slen )
        rec$slen = routing$slen;
    if ( routing?$sadr )
        rec$sadr = routing$sadr;
    if ( routing?$dnet )
        rec$dnet = routing$dnet;
    if ( routing?$dlen )
        rec$dlen = routing$dlen;
    if ( routing?$dadr )
        rec$dadr = routing$dadr;
    if ( routing?$fwd_ip )
        rec$fwd_ip = routing$fwd_ip;
    if ( routing?$fwd_port )
        rec$fwd_port = routing$fwd_port;
}

function apply_routing_device_control(c: connection, rec: BACnet_Device_Control)
{
    if ( ! has_routing(c, rec$is_orig) )
        return;

    local routing = c$bacnet_routing;

    if ( routing?$snet )
        rec$snet = routing$snet;
    if ( routing?$slen )
        rec$slen = routing$slen;
    if ( routing?$sadr )
        rec$sadr = routing$sadr;
    if ( routing?$dnet )
        rec$dnet = routing$dnet;
    if ( routing?$dlen )
        rec$dlen = routing$dlen;
    if ( routing?$dadr )
        rec$dadr = routing$dadr;
    if ( routing?$fwd_ip )
        rec$fwd_ip = routing$fwd_ip;
    if ( routing?$fwd_port )
        rec$fwd_port = routing$fwd_port;
}

###################################################################################################
#####  Records bacnet_bvlc_header event -> identity of the packet the routing state belongs to  ####
###################################################################################################
event bacnet_bvlc_header(c: connection,
                         is_orig: bool,
                         bvlc_function: count,
                         length: count,
                         pdu_seq: count){

    # Two guards, either of which is sufficient on its own. Recording the sequence number is what
    # scopes the stash to this packet, and discarding whatever the packet before left behind means
    # there is nothing for this packet to read back even if the sequence numbers were ever to
    # repeat. The analyzer generates this event from the outermost header of the datagram, ahead
    # of everything the datagram contains, so both happen before anything can stash or read.
    c$bacnet_pdu_seq = pdu_seq;
    delete c$bacnet_routing;
}

###################################################################################################
#######  Records bacnet_npdu_source event -> snet/slen/sadr columns on this packet's logs  ########
###################################################################################################
event bacnet_npdu_source(c: connection,
                         is_orig: bool,
                         snet: count,
                         slen: count,
                         sadr: string){

    local routing = routing_state(c, is_orig);

    routing$snet = snet;
    routing$slen = slen;

    # SLEN of 0 means broadcast on the source network, in which case SADR is zero bytes long.
    if ( slen > 0 && sadr != "" )
        routing$sadr = sadr;
}

###################################################################################################
####  Records bacnet_npdu_destination event -> dnet/dlen/dadr columns on this packet's logs  ######
###################################################################################################
event bacnet_npdu_destination(c: connection,
                              is_orig: bool,
                              dnet: count,
                              dlen: count,
                              dadr: string){

    local routing = routing_state(c, is_orig);

    routing$dnet = dnet;
    routing$dlen = dlen;

    # DLEN of 0 means broadcast on the destination network, in which case DADR is zero bytes long.
    if ( dlen > 0 && dadr != "" )
        routing$dadr = dadr;
}

###################################################################################################
###  Records bacnet_forwarded_npdu event -> fwd_ip/fwd_port columns on this packet's logs  ########
###################################################################################################
event bacnet_forwarded_npdu(c: connection,
                            is_orig: bool,
                            orig_ip: addr,
                            orig_port: count){

    local routing = routing_state(c, is_orig);

    routing$fwd_ip = orig_ip;
    routing$fwd_port = count_to_port(orig_port, udp);
}

###################################################################################################
###################  Defines logging of bacnet_apdu_header event -> bacnet.log  ###################
###################################################################################################
event bacnet_apdu_header(c: connection,
                         is_orig: bool,
                         bvlc_function: count,
                         pdu_type: count,
                         pdu_service: count,
                         invoke_id: count,
                         result_code: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    bacnet_log$is_orig = is_orig;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    if(is_orig)
    {
        bacnet_log$source_h         = c$id$orig_h;
        bacnet_log$source_p         = c$id$orig_p;
        bacnet_log$destination_h    = c$id$resp_h;
        bacnet_log$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_log$source_h         = c$id$resp_h;
        bacnet_log$source_p         = c$id$resp_p;
        bacnet_log$destination_h    = c$id$orig_h;
        bacnet_log$destination_p    = c$id$orig_p;
    }

    bacnet_log$bvlc_function = bvlc_functions[bvlc_function];

    if (bvlc_function == 0)
        bacnet_log$result_code = bvlc_results[result_code];

    if(pdu_type in apdu_types){
        bacnet_log$pdu_type = apdu_types[pdu_type];

        if (pdu_type != 1)
            bacnet_log$invoke_id = invoke_id;
    }

    switch(pdu_type){
        case 5:
            bacnet_log$result_code = error_codes[result_code];
            bacnet_log$pdu_service = "error";
            fallthrough;
        case 0:
            fallthrough;
        case 2:
            fallthrough;
        case 3:
            bacnet_log$pdu_service = confirmed_service_choice[pdu_service];
            break;
        case 1:
            bacnet_log$pdu_service = unconfirmed_service_choice[pdu_service];
            break;
        case 6:
            bacnet_log$result_code = reject_reasons[result_code];
            bacnet_log$pdu_service = "reject";
            break;
        case 7:
            bacnet_log$result_code = abort_reasons[result_code];
            bacnet_log$pdu_service = "abort";
            break;
        default:
            break;
    }

    apply_routing_header(c, bacnet_log);

    Log::write(LOG_BACNET, bacnet_log);
}

###################################################################################################
###################  Defines logging of bacnet_npdu_header event -> bacnet.log  ###################
###################################################################################################
event bacnet_npdu_header(c: connection,
                         is_orig: bool,
                         bvlc_function: count,
                         npdu_message_type: count){

    set_service(c);
    local bacnet_log: BACnet_Header;
    bacnet_log$is_orig = is_orig;
    bacnet_log$ts  = network_time();
    bacnet_log$uid = c$uid;
    bacnet_log$id  = c$id;

    if(is_orig)
    {
        bacnet_log$source_h         = c$id$orig_h;
        bacnet_log$source_p         = c$id$orig_p;
        bacnet_log$destination_h    = c$id$resp_h;
        bacnet_log$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_log$source_h         = c$id$resp_h;
        bacnet_log$source_p         = c$id$resp_p;
        bacnet_log$destination_h    = c$id$orig_h;
        bacnet_log$destination_p    = c$id$orig_p;
    }

    bacnet_log$bvlc_function = bvlc_functions[bvlc_function];

    bacnet_log$pdu_type = "NPDU";
    bacnet_log$pdu_service = npdu_message_types[npdu_message_type];

    apply_routing_header(c, bacnet_log);

    Log::write(LOG_BACNET, bacnet_log);
}

###################################################################################################
################  Defines logging of bacnet_who_is event -> bacnet_discovery.log  #################
###################################################################################################
event bacnet_who_is(c: connection,
                    is_orig: bool,
                    low_limit: count,
                    high_limit: count){

    set_service(c);
    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$is_orig = is_orig;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    if(is_orig)
    {
        bacnet_discovery$source_h         = c$id$orig_h;
        bacnet_discovery$source_p         = c$id$orig_p;
        bacnet_discovery$destination_h    = c$id$resp_h;
        bacnet_discovery$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_discovery$source_h         = c$id$resp_h;
        bacnet_discovery$source_p         = c$id$resp_p;
        bacnet_discovery$destination_h    = c$id$orig_h;
        bacnet_discovery$destination_p    = c$id$orig_p;
    }

    bacnet_discovery$pdu_service = "who-is";

    if(low_limit == UINT32_MAX)
        bacnet_discovery$range = "All";
    else
        bacnet_discovery$range = fmt("%d-%d", low_limit, high_limit);

    apply_routing_discovery(c, bacnet_discovery);

    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
#################  Defines logging of bacnet_i_am event -> bacnet_discovery.log  ##################
###################################################################################################
event bacnet_i_am(c: connection,
                  is_orig: bool,
                  object_type: count,
                  instance_number: count,
                  max_apdu: count,
                  segmentation: count,
                  vendor_id: count){

    set_service(c);
    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$is_orig = is_orig;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    if(is_orig)
    {
        bacnet_discovery$source_h         = c$id$orig_h;
        bacnet_discovery$source_p         = c$id$orig_p;
        bacnet_discovery$destination_h    = c$id$resp_h;
        bacnet_discovery$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_discovery$source_h         = c$id$resp_h;
        bacnet_discovery$source_p         = c$id$resp_p;
        bacnet_discovery$destination_h    = c$id$orig_h;
        bacnet_discovery$destination_p    = c$id$orig_p;
    }

    bacnet_discovery$pdu_service = "i-am";
    if(object_type != UINT32_MAX)
        bacnet_discovery$object_type = object_types[object_type];
    if(instance_number != UINT32_MAX)
        bacnet_discovery$instance_number = instance_number;
    bacnet_discovery$vendor = vendors[vendor_id];

    apply_routing_discovery(c, bacnet_discovery);

    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
################  Defines logging of bacnet_who_has event -> bacnet_discovery.log  ################
###################################################################################################
event bacnet_who_has(c: connection,
                     is_orig: bool,
                     low_limit: count,
                     high_limit: count,
                     object_type: count,
                     instance_number: count,
                     object_name: string){

    set_service(c);
    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$is_orig = is_orig;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    if(is_orig)
    {
        bacnet_discovery$source_h         = c$id$orig_h;
        bacnet_discovery$source_p         = c$id$orig_p;
        bacnet_discovery$destination_h    = c$id$resp_h;
        bacnet_discovery$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_discovery$source_h         = c$id$resp_h;
        bacnet_discovery$source_p         = c$id$resp_p;
        bacnet_discovery$destination_h    = c$id$orig_h;
        bacnet_discovery$destination_p    = c$id$orig_p;
    }

    bacnet_discovery$pdu_service = "who-has";

    if(instance_number != UINT32_MAX){
        bacnet_discovery$object_type = object_types[object_type];
        bacnet_discovery$instance_number = instance_number;
    }

    if(object_name == "")
        bacnet_discovery$object_name = "N/A";
    else
        bacnet_discovery$object_name = object_name;

    if(low_limit == UINT32_MAX)
        bacnet_discovery$range = "All";
    else
        bacnet_discovery$range = fmt("%d-%d", low_limit, high_limit);

    apply_routing_discovery(c, bacnet_discovery);

    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
################  Defines logging of bacnet_i_have event -> bacnet_discovery.log  #################
###################################################################################################
event bacnet_i_have(c: connection,
                    is_orig: bool,
                    device_object_type: count,
                    device_instance_num: count,
                    object_object_type: count,
                    object_instance_num: count,
                    object_name: string){

    set_service(c);
    local bacnet_discovery: BACnet_Discovery;
    bacnet_discovery$is_orig = is_orig;
    bacnet_discovery$ts  = network_time();
    bacnet_discovery$uid = c$uid;
    bacnet_discovery$id  = c$id;

    if(is_orig)
    {
        bacnet_discovery$source_h         = c$id$orig_h;
        bacnet_discovery$source_p         = c$id$orig_p;
        bacnet_discovery$destination_h    = c$id$resp_h;
        bacnet_discovery$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_discovery$source_h         = c$id$resp_h;
        bacnet_discovery$source_p         = c$id$resp_p;
        bacnet_discovery$destination_h    = c$id$orig_h;
        bacnet_discovery$destination_p    = c$id$orig_p;
    }

    bacnet_discovery$pdu_service = "i-have";

    if(device_object_type != UINT32_MAX)
        bacnet_discovery$device_id_type = object_types[device_object_type];

    if(device_instance_num != UINT32_MAX)
        bacnet_discovery$device_id_number = device_instance_num;
           
    if(object_object_type != UINT32_MAX)
        bacnet_discovery$object_type = object_types[object_object_type];

    if(object_instance_num != UINT32_MAX)
        bacnet_discovery$instance_number = object_instance_num;

    bacnet_discovery$object_name = object_name;

    apply_routing_discovery(c, bacnet_discovery);

    Log::write(LOG_BACNET_DISCOVERY, bacnet_discovery);
}

###################################################################################################
#############  Defines logging of bacnet_read_property event -> bacnet_property.log  ##############
###################################################################################################
event bacnet_read_property(c: connection,
                           is_orig: bool,
                           invoke_id: count,
                           pdu_service: string,
                           object_type: count,
                           instance_number: count,
                           property_identifier: count,
                           property_array_index: count){

    set_service(c);
    local bacnet_property: BACnet_Property;
    bacnet_property$is_orig = is_orig;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    if(is_orig)
    {
        bacnet_property$source_h         = c$id$orig_h;
        bacnet_property$source_p         = c$id$orig_p;
        bacnet_property$destination_h    = c$id$resp_h;
        bacnet_property$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_property$source_h         = c$id$resp_h;
        bacnet_property$source_p         = c$id$resp_p;
        bacnet_property$destination_h    = c$id$orig_h;
        bacnet_property$destination_p    = c$id$orig_p;
    }

    bacnet_property$invoke_id  = invoke_id;

    bacnet_property$pdu_service = pdu_service;
    bacnet_property$object_type = object_types[object_type];
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];

    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;

    apply_routing_property(c, bacnet_property);

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
###########  Defines logging of bacnet_read_property_ack event -> bacnet_property.log  ############
###################################################################################################
event bacnet_read_property_ack(c: connection,
                               is_orig: bool,
                               invoke_id: count,
                               pdu_service: string,
                               object_type: count,
                               instance_number: count,
                               property_identifier: count,
                               property_array_index: count,
                               property_value: string){

    set_service(c);
    local bacnet_property: BACnet_Property;
    bacnet_property$is_orig = is_orig;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    if(is_orig)
    {
        bacnet_property$source_h         = c$id$orig_h;
        bacnet_property$source_p         = c$id$orig_p;
        bacnet_property$destination_h    = c$id$resp_h;
        bacnet_property$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_property$source_h         = c$id$resp_h;
        bacnet_property$source_p         = c$id$resp_p;
        bacnet_property$destination_h    = c$id$orig_h;
        bacnet_property$destination_p    = c$id$orig_p;
    }

    
    bacnet_property$invoke_id  = invoke_id;

    bacnet_property$pdu_service = pdu_service;
    bacnet_property$object_type = object_types[object_type];
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];

    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;

    if (property_value != "" && is_num(property_value)) {
        switch(property_identifier){
            case 36:
                bacnet_property$value = event_states[to_count(property_value)];
                break;
            case 72:
                bacnet_property$value = notify_type[to_count(property_value)];
                break;
            case 79:
                bacnet_property$value = object_types[to_count(property_value)];
                break;
            case 103:
                bacnet_property$value = reliability[to_count(property_value)];
                break;
            case 107:
                bacnet_property$value = segmentation_supported_status[to_count(property_value)];
                break;
            case 112:
                bacnet_property$value = device_status[to_count(property_value)];
                break;
            case 117:
                bacnet_property$value = bacnet_units[to_count(property_value)];
                break;
            case 197:
                bacnet_property$value = logging_type[to_count(property_value)];
                break;
            default:
                if (property_value != "")
                    bacnet_property$value = property_value;
                break;
        }
    } else if (property_value != "") {
        bacnet_property$value = property_value;
    }

    apply_routing_property(c, bacnet_property);

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
#############  Defines logging of bacnet_write_property event -> bacnet_property.log  #############
###################################################################################################
event bacnet_write_property(c: connection,
                            is_orig: bool,
                            invoke_id: count,
                            object_type: count,
                            instance_number: count,
                            property_identifier: count,
                            property_array_index: count,
                            priority: count,
                            property_value: string){

    set_service(c);
    local bacnet_property: BACnet_Property;
    bacnet_property$is_orig = is_orig;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    if(is_orig)
    {
        bacnet_property$source_h         = c$id$orig_h;
        bacnet_property$source_p         = c$id$orig_p;
        bacnet_property$destination_h    = c$id$resp_h;
        bacnet_property$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_property$source_h         = c$id$resp_h;
        bacnet_property$source_p         = c$id$resp_p;
        bacnet_property$destination_h    = c$id$orig_h;
        bacnet_property$destination_p    = c$id$orig_p;
    }

    
    bacnet_property$invoke_id  = invoke_id;

    bacnet_property$pdu_service = "write-property";
    bacnet_property$object_type = object_types[object_type];
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];

    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;

    # Priority is optional in the Write-Property request. The analyzer signals its absence with
    # UINT8_MAX, which is not a legal BACnet priority, so it is left unset rather than logged.
    if( priority != UINT8_MAX )
        bacnet_property$priority = priority;

    if (property_value != "" && is_num(property_value)) {
        switch(property_identifier){
            case 36:
                bacnet_property$value = event_states[to_count(property_value)];
                break;
            case 72:
                bacnet_property$value = notify_type[to_count(property_value)];
                break;
            case 79:
                bacnet_property$value = object_types[to_count(property_value)];
                break;
            case 103:
                bacnet_property$value = reliability[to_count(property_value)];
                break;
            case 107:
                bacnet_property$value = segmentation_supported_status[to_count(property_value)];
                break;
            case 112:
                bacnet_property$value = device_status[to_count(property_value)];
                break;
            case 117:
                bacnet_property$value = bacnet_units[to_count(property_value)];
                break;
            case 197:
                bacnet_property$value = logging_type[to_count(property_value)];
                break;
            default:
                if (property_value != "")
                    bacnet_property$value = property_value;
                break;
        }
    } else if (property_value != "") {
        bacnet_property$value = property_value;
    }

    apply_routing_property(c, bacnet_property);

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
#############  Defines logging of bacnet_property_error event -> bacnet_property.log  #############
###################################################################################################
event bacnet_property_error(c: connection,
                            is_orig: bool,
                            invoke_id: count,
                            pdu_type: count,
                            pdu_service: count,
                            result_code: count){

    set_service(c);
    local bacnet_property: BACnet_Property;
    bacnet_property$is_orig = is_orig;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    if(is_orig)
    {
        bacnet_property$source_h         = c$id$orig_h;
        bacnet_property$source_p         = c$id$orig_p;
        bacnet_property$destination_h    = c$id$resp_h;
        bacnet_property$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_property$source_h         = c$id$resp_h;
        bacnet_property$source_p         = c$id$resp_p;
        bacnet_property$destination_h    = c$id$orig_h;
        bacnet_property$destination_p    = c$id$orig_p;
    }

    
    bacnet_property$invoke_id  = invoke_id;

    bacnet_property$pdu_service = "ERROR: " + confirmed_service_choice[pdu_service];
    bacnet_property$object_type = error_codes[result_code];

    apply_routing_property(c, bacnet_property);

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

event bacnet_read_range(c: connection,
                        is_orig: bool,
                        invoke_id: count,
                        object_type: count,
                        instance_number: count,
                        property_identifier: count,
                        property_array_index: count){

    set_service(c);
    local bacnet_property: BACnet_Property;
    bacnet_property$is_orig = is_orig;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    if(is_orig)
    {
        bacnet_property$source_h         = c$id$orig_h;
        bacnet_property$source_p         = c$id$orig_p;
        bacnet_property$destination_h    = c$id$resp_h;
        bacnet_property$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_property$source_h         = c$id$resp_h;
        bacnet_property$source_p         = c$id$resp_p;
        bacnet_property$destination_h    = c$id$orig_h;
        bacnet_property$destination_p    = c$id$orig_p;
    }

    
    bacnet_property$invoke_id  = invoke_id;

    bacnet_property$pdu_service = "read-range-request";
    bacnet_property$object_type = object_types[object_type];
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];

    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;

    apply_routing_property(c, bacnet_property);

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

event bacnet_read_range_ack(c: connection,
                            is_orig: bool,
                            invoke_id: count,
                            object_type: count,
                            instance_number: count,
                            property_identifier: count,
                            property_array_index: count,
                            result_flags: count,
                            item_count: count){

    set_service(c);
    local bacnet_property: BACnet_Property;
    bacnet_property$is_orig = is_orig;
    bacnet_property$ts  = network_time();
    bacnet_property$uid = c$uid;
    bacnet_property$id  = c$id;

    if(is_orig)
    {
        bacnet_property$source_h         = c$id$orig_h;
        bacnet_property$source_p         = c$id$orig_p;
        bacnet_property$destination_h    = c$id$resp_h;
        bacnet_property$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_property$source_h         = c$id$resp_h;
        bacnet_property$source_p         = c$id$resp_p;
        bacnet_property$destination_h    = c$id$orig_h;
        bacnet_property$destination_p    = c$id$orig_p;
    }

    
    bacnet_property$invoke_id  = invoke_id;

    bacnet_property$pdu_service = "read-range-ack";
    bacnet_property$object_type = object_types[object_type];
    bacnet_property$instance_number = instance_number;
    bacnet_property$property = property_identifiers[property_identifier];

    if( property_array_index != UINT32_MAX )
        bacnet_property$array_index = property_array_index;

    bacnet_property$value = fmt("item_count: %d",item_count);

    apply_routing_property(c, bacnet_property);

    Log::write(LOG_BACNET_PROPERTY, bacnet_property);
}

###################################################################################################
#######  Defines logging of bacnet_reinitialize_device event -> bacnet_device_control.log  ########
###################################################################################################
event bacnet_reinitialize_device(c: connection,
                                 is_orig: bool,
                                 invoke_id: count,
                                 reinitialized_state: count,
                                 password: string){

    set_service(c);
    local bacnet_device_control: BACnet_Device_Control;
    bacnet_device_control$is_orig = is_orig;
    bacnet_device_control$ts  = network_time();
    bacnet_device_control$uid = c$uid;
    bacnet_device_control$id  = c$id;

    if(is_orig)
    {
        bacnet_device_control$source_h         = c$id$orig_h;
        bacnet_device_control$source_p         = c$id$orig_p;
        bacnet_device_control$destination_h    = c$id$resp_h;
        bacnet_device_control$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_device_control$source_h         = c$id$resp_h;
        bacnet_device_control$source_p         = c$id$resp_p;
        bacnet_device_control$destination_h    = c$id$orig_h;
        bacnet_device_control$destination_p    = c$id$orig_p;
    }

    

    bacnet_device_control$invoke_id = invoke_id;
    bacnet_device_control$pdu_service = "reinitialize_device";
    bacnet_device_control$device_state = reinitialize_device_states[reinitialized_state];
    bacnet_device_control$password = password;
    
    apply_routing_device_control(c, bacnet_device_control);

    Log::write(LOG_BACNET_DEVICE_CONTROL, bacnet_device_control);
}

###################################################################################################
########  Defines logging of bacnet_device_control_response event -> bacnet_device_control.log  #####
###################################################################################################
event bacnet_device_control_response(c: connection,
                                     is_orig: bool,
                                     invoke_id: count,
                                     pdu_service: count,
                                     pdu_type: count,
                                     result_code: count){

    set_service(c);
    local bacnet_device_control: BACnet_Device_Control;
    bacnet_device_control$is_orig = is_orig;
    bacnet_device_control$ts  = network_time();
    bacnet_device_control$uid = c$uid;
    bacnet_device_control$id  = c$id;

    if(is_orig)
    {
        bacnet_device_control$source_h         = c$id$orig_h;
        bacnet_device_control$source_p         = c$id$orig_p;
        bacnet_device_control$destination_h    = c$id$resp_h;
        bacnet_device_control$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_device_control$source_h         = c$id$resp_h;
        bacnet_device_control$source_p         = c$id$resp_p;
        bacnet_device_control$destination_h    = c$id$orig_h;
        bacnet_device_control$destination_p    = c$id$orig_p;
    }

    bacnet_device_control$invoke_id = invoke_id;
    bacnet_device_control$pdu_service = confirmed_service_choice[pdu_service];

    switch(pdu_type){
        case 2:
            bacnet_device_control$result = "SUCCESS";
            break;
        case 5:
            bacnet_device_control$result = "ERROR";
            bacnet_device_control$result_code = error_codes[result_code];
            break;
        case 6:
            bacnet_device_control$result = "REJECT";
            bacnet_device_control$result_code = reject_reasons[result_code];
            break;
        case 7:
            bacnet_device_control$result = "ABORT";
            bacnet_device_control$result_code = abort_reasons[result_code];
            break;
        default:
            break;
    }

    apply_routing_device_control(c, bacnet_device_control);

    Log::write(LOG_BACNET_DEVICE_CONTROL, bacnet_device_control);
}

###################################################################################################
###  Defines logging of bacnet_device_communication_control event -> bacnet_device_control.log  ###
###################################################################################################
event bacnet_device_communication_control(c: connection,
                                          is_orig: bool,
                                          invoke_id: count,
                                          time_duration: count,
                                          enable_disable: count,
                                          password: string){

    set_service(c);
    local bacnet_device_control: BACnet_Device_Control;
    bacnet_device_control$is_orig = is_orig;
    bacnet_device_control$ts  = network_time();
    bacnet_device_control$uid = c$uid;
    bacnet_device_control$id  = c$id;

    if(is_orig)
    {
        bacnet_device_control$source_h         = c$id$orig_h;
        bacnet_device_control$source_p         = c$id$orig_p;
        bacnet_device_control$destination_h    = c$id$resp_h;
        bacnet_device_control$destination_p    = c$id$resp_p;
    }else
    {
        bacnet_device_control$source_h         = c$id$resp_h;
        bacnet_device_control$source_p         = c$id$resp_p;
        bacnet_device_control$destination_h    = c$id$orig_h;
        bacnet_device_control$destination_p    = c$id$orig_p;
    }

    bacnet_device_control$invoke_id = invoke_id;
    bacnet_device_control$pdu_service = "device_communication_control";
    if( time_duration != UINT32_MAX )
        bacnet_device_control$time_duration = time_duration;
    bacnet_device_control$device_state = device_communication_control_states[enable_disable];
    bacnet_device_control$password = password;

    apply_routing_device_control(c, bacnet_device_control);

    Log::write(LOG_BACNET_DEVICE_CONTROL, bacnet_device_control);
}
