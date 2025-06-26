## bacnet-analyzer.pac
##
## Binpac BACnet Protocol Analyzer - Defines a connection, flow, and other processing functions for the analyzer.
##
## Author:  Stephen Kleinheider
## Contact: stephen.kleinheider@inl.gov
##
## Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

%extern{
    #include "zeek/file_analysis/Manager.h"
%}

%header{

    static string object_types[] = {"analog-input","analog-output","analog-value","binary-input","binary-output","binary-value","calendar","command","device","event-enrollment","file","group","loop","multi-state-input","multi-state-output","notification-class","program","schedule","averaging","multi-state-value","trend-log","life-safety-point","life-safety-zone","accumulator","pulse-converter","event-log","global-group","trend-log-multiple","load-control","structured-view","access-door","access-credential","access-point","access-rights","access-user","access-zone","credential-data-input","network-security","bitstring-value","characterstring-value","date-pattern-value","date-value","datetime-pattern-value","datetime-value","integer-value","large-analog-value","octetstring-value","positive-integer-value","time-pattern-value","time-value"};

    // BACnetObjectIdentifier Object
    typedef struct BACnetObjectIdentifier
    {
        uint32 object_type, instance_number;

        // Initializes BACnetObjectIdentifier object with default data
        BACnetObjectIdentifier()
        {
            object_type = UINT32_MAX;
            instance_number = UINT32_MAX;
        }
        // Creates BACnetObjectIdentifier object from BACnet Tag data
        BACnetObjectIdentifier( const_bytestring data )
        {
            if ( data.length() == 4 )
            {
                object_type = (data[0] << 2) + (data[1] >> 6);
                instance_number = ((data[1] & 0x3f) << 16) + (data[2] << 8) + data[3];
            }
            else
            {
                object_type = UINT32_MAX;
                instance_number = UINT32_MAX;
            }
        }
    }BACnetObjectIdentifier;

    // BACnetDate Object
    typedef struct BACnetDate
    {
        uint16 year, month, day, day_of_week;

        // Creates BACnetDate object from BACnet Tag data
        BACnetDate( const_bytestring data )
        {
            if ( data.length() == 4 )
            {
                year = 1900 + data[0];
                month = data[1];
                day = data[2];
                day_of_week = data[3];
            }
            else
            {
                year = UINT16_MAX;
                month = UINT16_MAX;
                day = UINT16_MAX;
                day_of_week = UINT16_MAX;
            }
        }
    }BACnetDate;

    // BACnetTime Object
    typedef struct BACnetTime
    {
        uint16 hour, minute, second, millisecond;

        // Creates BACnetTime object from BACnet Tag data
        BACnetTime( const_bytestring data )
        {
            if ( data.length() == 4 )
            {
                hour = data[0];
                minute = data[1];
                second = data[2];
                millisecond = data[3];
            }
            else
            {
                hour = UINT16_MAX;
                minute = UINT16_MAX;
                second = UINT16_MAX;
                millisecond = UINT16_MAX;
            }
        }
    }BACnetTime;

    int32 get_signed(const_bytestring data);
    uint32 get_unsigned(const_bytestring data);
    float get_float(const_bytestring data);
    double get_double(const_bytestring data);
    string get_string(const_bytestring data);
    string get_string2(const_bytestring data);

    string parse_tag(uint8 tag_num, uint8 tag_class, const_bytestring data, uint32 tag_length, uint32 tag_length_a);

    %}

%code{
    // Parses Application Tag based on tag_num and returns string representation of data
    string parse_tag(uint8 tag_num, uint8 tag_class, const_bytestring data, uint32 tag_length, uint32 tag_length_a)
    {
        string str = "";
        switch(tag_num){
            case 0: // Null
                return str;
            case 1: // Boolean
                return tag_length_a==1 ? "true" : "false";
            case 2: // Unsigned Integer
                return to_string(get_unsigned(data));
            case 3: // Signed Integer
                return to_string(get_signed(data));
            case 4: // Real (ANSI/IEEE-754 floating point)
                return to_string(get_float(data));
            case 5: // Double (ANSI/IEEE-754 double precision floating point)
                return to_string(get_double(data));
            case 6: // Octet String
                {
                    // If the payload is extremely large, avoid allocating a gigantic string.
                    if ( data.length() > 1024 )
                        return zeek::util::fmt("<octets len=%d>", data.length());

                    // Reserve exact space (2 hex chars per byte) to avoid repeated reallocs.
                    str.reserve(data.length() * 2);

                    static const char hexmap[] = "0123456789abcdef";
                    for ( int32 i = 0; i < data.length(); ++i )
                    {
                        uint8 b = data[i];
                        str.push_back(hexmap[b >> 4]);
                        str.push_back(hexmap[b & 0x0F]);
                    }
                    return str;
                }
            case 7: // Character String
                return get_string(data);
            case 8: // Bit String
                {
                    if ( data.length() > 512 )
                        return zeek::util::fmt("<bits len=%d>", data.length());

                    if ( data.length() <= 1 )
                        return str; // empty bitstring

                    str.reserve((data.length()-1)*8);
                    for( int32 j = 1; j < data.length(); ++j){
                        for( int8 i = 7; i >= 0; --i)
                            str += ((data[j]>>i)&1)==1 ? 'T' : 'F';
                    }
                    return str;
                }
            case 9: // Enumerated
                return to_string(get_unsigned(data));
            case 10: // BACnetDate
                if(data.length() == 4)
                    str += zeek::util::fmt("%d/%d/%d",data[1],data[2],data[0]+1900);
                return str;
            case 11: // BACnetTime
                if(data.length() == 4)
                    str += zeek::util::fmt("%d:%d:%d.%d",data[0],data[1],data[2],data[3]);
                return str;
            case 12: // BACnetObjectIdentifier
                if(data.length() == 4)
                {
                    uint32 idx = (data[0] << 2) + (data[1] >> 6);
                    if ( idx < (sizeof(object_types) / sizeof(object_types[0])) )
                        str += object_types[idx];
                    else
                        str += zeek::util::fmt("unknown_type_%u", idx);

                    str += zeek::util::fmt(": %u", ((data[1] & 0x3f) << 16) + (data[2] << 8) + data[3]);
                }
                return str;
            default:
                return str;
        }
    }

    // Converts BACnet Tag data to int32
    int32 get_signed(const_bytestring data)
    {
        uint32 number = 0;
        int32 ret_val = 0;
        if ( data.length() == 1 )
        {
            number = data[0];
            int8 tmp = (int)number;
            ret_val = tmp;
        }
        else if ( data.length() == 2 )
        {
            number = (data[0] << 8) + data[1];
            int16 tmp = (int)number;
            ret_val = tmp;
        }
        else if ( data.length() == 4 )
        {
            number = (data[0] << 16) + (data[1] << 8) + data[2];
            int32 tmp = (int)number;
            ret_val = tmp;
        }
        return ret_val;
    }

    // Converts BACnet Tag data to uint32
    uint32 get_unsigned(const_bytestring data)
    {
        uint32 number = 0;
        for ( int32 i = 0; i < data.length(); ++i ){
            number <<= 8;
            number |= data[i];

            if ( i == 3 )
                return number;
        }
        return number;
    }

    // Converts BACnet Tag data to float
    float get_float(const_bytestring data)
    {
        char float_result[4];
        if ( data.length() != 4 )
            return 0;

        for( uint8 i = 0; i < 4; ++i)
            float_result[i] = data[3-i];

        return *((float*)float_result);
    }

    // Converts BACnet Tag data to double
    double get_double(const_bytestring data)
    {
        if ( data.length() != 8 )
            return 0;

        char double_result[8];
        for( uint8 i = 0; i < 8; ++i)
            double_result[i] = data[8-i];
    
        return *((double*)double_result);
    }

    // Converts BACnet Tag data (character string with UTF-8 indicator) to Zeek string
    string get_string(const_bytestring data)
    {
        string str = "";

        if ( data.length() == 0 )
            return str;

        if ( data[0] != 0 )
            return str; // not UTF-8, ignore to match baseline

        int32 start = 1;

        if ( data.length() - 1 > 4096 )
            return zeek::util::fmt("<string len=%d>", data.length() - 1);

        for ( int32 i = 1; i < data.length(); ++i )
        {
            if ( data[i] == 0 )
                break;          // stop at embedded NUL

            str += data[i];
        }

        return str;
    }

    // Raw string helper that keeps original bytes (up to limit) and stops at NUL
    string get_string2(const_bytestring data)
    {
        string str = "";

        if ( data.length() > 4096 )
            return zeek::util::fmt("<string len=%d>", data.length());

        for ( int32 i = 0; i < data.length(); ++i )
        {
            if ( data[i] == 0 )
                break;

            str += data[i];
        }

        return str;
    }

    %}


refine flow BACNET_Flow += {

    %member{
        //
        // Vector of uint8 that holds segmented data.  This is the underlying/backing structure
        // for the const_bytestring that gets passed between the buffer_service_tags function
        // and the process_service_tags function via the Binpac $context.flow.
        // 
        vector<binpac::uint8> segmented_data_buffer;
    %}

    function process_service_tags(data: const_bytestring): BACnet_Tag[]
        %{
            //
            // The code used to parse the bytestring data into a BACnet_Tag array
            // was taken directly from the build/bacnet.cc code which is the result
            // of "compiling" the bacnet-protocol.pac file.  Specifically, the binpac 
            // code 'service_tags : BACnet_Tag[] &until($input == 0);' ends up
            // as the following C code.
            //
            vector<BACnet_Tag *> * service_tags_ = new vector<BACnet_Tag *>;
            BACnet_Tag * service_tags__elem_;
	        const_byteptr t_service_tags__elem__dataptr = &data[0];
	        const_byteptr t_end_of_data = &data[data.length() - 1];
	        int t_service_tags__elem__it = 0;
            int t_byteorder = bigendian;

            for (; ; ++t_service_tags__elem__it)
            {
                // Check &until(service_tags__elem__dataptr >= end_of_data)
                if ( t_service_tags__elem__dataptr >= t_end_of_data )
                {
                    service_tags__elem_ = nullptr;
                    goto end_of_service_tags;
                }
                service_tags__elem_ = new BACnet_Tag();
                int t_service_tags__elem__size;
                t_service_tags__elem__size = service_tags__elem_->Parse(t_service_tags__elem__dataptr, t_end_of_data, t_byteorder);
                service_tags_->push_back(service_tags__elem_);
                
                t_service_tags__elem__dataptr += t_service_tags__elem__size;
                BINPAC_ASSERT(t_service_tags__elem__dataptr <= t_end_of_data);
                service_tags__elem_ = nullptr;
            }

            end_of_service_tags: ;

            // Clear the underlying buffer
            segmented_data_buffer.clear();

            return service_tags_;

        %}

    function buffer_service_tags(data: const_bytestring, more_follows: bool): const_bytestring
        %{
            for(int i=0; i<data.length(); i++) {
                segmented_data_buffer.push_back(data[i]);
            }

            // Due to what I believe is a bug with how the Binpac implementation handles &restofdata,
            // a null byte needs to be appended to the end of the segmented_data_buffer.  Given Binpac
            // is no longer supported, it's a non starter to submit a bug report.  We'll just "fix it"
            // here and be on our way.
            if (more_follows == 0) {
                uint8 null_byte = 0x00;
                segmented_data_buffer.push_back(null_byte);
            }

            return const_bytestring(segmented_data_buffer.data(), segmented_data_buffer.size());
        %}

    ###################################################################################################
    ##################################### GENERAL BACNET MESSAGE ######################################
    ###################################################################################################

    ## -----------------------------------process_bacnet_apdu_header-----------------------------------
    ## General BACnet APDU Message Description:
    ##      This is the default message being logged by the parser to bacnet.log for APDU packets. 
    ##      Each BACnet APDU packet will create this message.
    ## General BACnet APDU Message Event Generation:
    ##      - bvlc_function     -> BVLC Function
    ##          + Matches bvlc_functions in consts.zeek
    ##      - pdu_type          -> APDU Type
    ##          + Matches apdu_types in consts.zeek
    ##      - pdu_service       -> APDU Service
    ##          + Matches unconfirmed_service_choice or confirmed_service_choice in consts.zeek
    ##      - invoke_id         -> Invoke ID
    ##          + Integer in the range 0-255 generated by the device issuing the service request. It
    ##            is unique for all outstanding confirmed request/ACK APDUs
    ##      - result_code       -> Error Code or Reject/Abort Reason
    ##          + Matches error_codes, reject_reasons, or abort_reasons in consts.zeek
    ## ------------------------------------------------------------------------------------------------
    function process_bacnet_apdu_header(is_orig: bool, bvlc_function: uint8, pdu_type: int8, pdu_service: int8, invoke_id: uint8, result_code: int8): bool
        %{
            if ( ::bacnet_apdu_header )
            {
                zeek::BifEvent::enqueue_bacnet_apdu_header(connection()->zeek_analyzer(),
                                                           connection()->zeek_analyzer()->Conn(),
                                                           is_orig,
                                                           bvlc_function,
                                                           pdu_type,
                                                           pdu_service,
                                                           invoke_id,
                                                           result_code);
            }
            if( ::bacnet_property_error && pdu_type == ERROR_PDU )
            {
                if( pdu_service == READ_PROPERTY || pdu_service == READ_PROPERTY_MULTIPLE || pdu_service == WRITE_PROPERTY || pdu_service == WRITE_PROPERTY_MULTIPLE )
                {
                    zeek::BifEvent::enqueue_bacnet_property_error(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  is_orig,
                                                                  invoke_id,
                                                                  pdu_type,
                                                                  pdu_service,
                                                                  result_code);
                }
            }
            if ( ::bacnet_device_control_response && (pdu_service == REINITIALIZE_DEVICE || pdu_service == DEVICE_COMMUNICATION_CONTROL) && (pdu_type == SIMPLE_ACK || pdu_type == ERROR_PDU || pdu_type == REJECT_PDU || pdu_type == ABORT_PDU))
            {
                zeek::BifEvent::enqueue_bacnet_device_control_response(connection()->zeek_analyzer(),
                                                                       connection()->zeek_analyzer()->Conn(),
                                                                       is_orig,
                                                                       invoke_id,
                                                                       pdu_service,
                                                                       pdu_type,
                                                                       result_code);
            }
            return true;
        %}

    ## -----------------------------------process_bacnet_npdu_header-----------------------------------
    ## General BACnet NPDU Message Description:
    ##      This is the default message being logged by the parser to bacnet.log for NPDU packets. 
    ##      Each BACnet NPDU packet will create this message.
    ## General BACnet NPDU Message Event Generation:
    ##      - bvlc_function       -> BVLC Function
    ##          + Matches bvlc_functions in consts.zeek
    ##      - npdu_message_type   -> NPDU Message Type
    ##          + Matches npdu_message_types in consts.zeek
    ## ------------------------------------------------------------------------------------------------
    function process_bacnet_npdu_header(is_orig: bool, bvlc_function: uint8, npdu_message_type: uint8): bool
        %{
            if ( ::bacnet_npdu_header )
            {
                zeek::BifEvent::enqueue_bacnet_npdu_header(connection()->zeek_analyzer(),
                                                           connection()->zeek_analyzer()->Conn(),
                                                           is_orig,
                                                           bvlc_function,
                                                           npdu_message_type);
            }
            return true;
        %}

    ###################################################################################################
    ################################## END OF GENERAL BACNET MESSAGE ##################################
    ###################################################################################################



    ###################################################################################################
    ################################## UNCONFIRMED SERVICE REQUESTS ###################################
    ###################################################################################################

    ## ------------------------------------------process_i_am------------------------------------------
    ## I-Am Description:
    ##      The I-Am service is used to respond to Who-Is service requests, however the request may be
    ##      issued at any time (can be issued without a Who_Is request)
    ## I-Am Structure:
    ##      - Device Identifier:        BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device
    ##      - Max APDU Length Accepted: uint8                   -> Mandatory
    ##          + Maximum number of bytes contained in a single APDU
    ##      - Segmentation Supported:   uint8                   -> Mandatory
    ##          + Conveys ability to process segmented messages
    ##      - Vendor Identifier:        uint32                  -> Mandatory
    ##          + Identity of vendor who manufactured the device
    ## I-Am Event Generation:
    ##      - object_type       -> Object Type from Device Identifier
    ##      - instance_number   -> Instance Number from Device Identifier
    ##      - max_apdu          -> Max APDU Length Accepted
    ##      - segmentation      -> Segmentation Supported
    ##      - vendor_id         -> Vendor ID
    ## ------------------------------------------------------------------------------------------------
    function process_i_am(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_i_am )
            {
                if ( ${tags}->size() == 4 )
                {
                    BACnetObjectIdentifier device_identifier;
                    if ( ${tags[0].tag_length} == 4 )
                        device_identifier = {${tags[0].tag_data}};
                    
                    uint8 max_apdu = ${tags[1].tag_data[0]};
                    uint8 segmentation_supported = ${tags[2].tag_data[0]};
                    uint32 vendor_id = get_unsigned(${tags[3].tag_data});
                
                    zeek::BifEvent::enqueue_bacnet_i_am(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        is_orig,
                                                        device_identifier.object_type,
                                                        device_identifier.instance_number,
                                                        max_apdu,
                                                        segmentation_supported,
                                                        vendor_id);
                }
            }
            return true;
        %}

    ## ------------------------------------------process_i_have------------------------------------------
    ## I-Have Description:
    ##      The I-Am service is used to respond to Who-Has service requests or to advertise the
    ##      existence of an object with a given Object Name or Object Identifier
    ## I-Have Structure:
    ##      - Device Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device initiating this request
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object being advertised
    ##      - Object Name:          string                  -> Mandatory
    ##          + Name of the object that is being advertised
    ## I-Have Event Generation:
    ##      - device_object_type        -> Object Type from Device Identifier
    ##      - device_instance_number    -> Instance Number from Device Identifier
    ##      - object_object_type        -> Object Type from Object Identifier
    ##      - object_instance_number    -> Instance Number from Object Identifier
    ##      - object_name               -> Object Name
    ## ------------------------------------------------------------------------------------------------
    function process_i_have(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_i_have )
            {
                BACnetObjectIdentifier device_identifier, object_identifier;
                string object_name = "";

                if ( ${tags}->size() > 0 && ${tags[0].tag_length} == 4 )
                    device_identifier = {${tags[0].tag_data}};
                
                if ( ${tags}->size() > 1 && ${tags[1].tag_length} == 4 )
                    object_identifier = {${tags[1].tag_data}};

                if ( ${tags}->size() > 2 )
                    object_name = get_string(${tags[2].tag_data});

                zeek::BifEvent::enqueue_bacnet_i_have(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      is_orig,
                                                      device_identifier.object_type,
                                                      device_identifier.instance_number,
                                                      object_identifier.object_type,
                                                      object_identifier.instance_number,
                                                      zeek::make_intrusive<zeek::StringVal>(object_name));
            }
            return true;
        %}

    ## ------------------------------process_unconfirmed_cov_notification------------------------------
    ## Unconfirmed-COV-Notification Description:
    ##      The Unconfirmed-COV-Notification is used to notify subscribers about changes that may have
    ##      occurred to the properties of a particular object
    ## Unconfirmed-COV-Notification Structure:
    ##      - Subscriber Process Identifier:    uint32                  -> Mandatory
    ##          + Numerical Handle meaningful to the subscriber
    ##      - Initiating Device Identifier:     BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device
    ##      - Monitored Object Identifier:      BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object that has changed
    ##      - Time Remaining:                   uint32                  -> Mandatory
    ##          + Remaining lifetime of the subscription in seconds
    ##      - List of Values:                   list                    -> Mandatory
    ##          + List of one or more property values
    ## Unconfirmed-COV-Notification Event Generation:
    ##      - subscriber_id                 -> Subscriber Process Identifier
    ##      - initiating_object_type        -> Object Type from Initiating Device Identifier
    ##      - initiating_instance_number    -> Instance Number from Initiating Device Identifier
    ##      - monitored_object_type         -> Object Type from Monitored Device Identifier
    ##      - monitored_instance_number     -> Instance Number from Monitored Device Identifier
    ##      - time_remaining                -> Time Remaining
    ## ------------------------------------------------------------------------------------------------
    function process_unconfirmed_cov_notification(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_unconfirmed_cov_notification )
            {
                uint32 subscriber_identifier = get_unsigned(${tags[0].tag_data});
                BACnetObjectIdentifier initiating_identifier = {${tags[1].tag_data}};
                BACnetObjectIdentifier monitored_identifier = {${tags[2].tag_data}};
                uint32 time_remaining = get_unsigned(${tags[3].tag_data});

                zeek::BifEvent::enqueue_bacnet_unconfirmed_cov_notification(connection()->zeek_analyzer(),
                                                                            connection()->zeek_analyzer()->Conn(),
                                                                            is_orig,
                                                                            subscriber_identifier,
                                                                            initiating_identifier.object_type,
                                                                            initiating_identifier.instance_number,
                                                                            monitored_identifier.object_type,
                                                                            monitored_identifier.instance_number,
                                                                            time_remaining);
            }
            return true;
        %}

    ## -----------------------------process_unconfirmed_event_notification-----------------------------
    ## Unconfirmed-Event-Notification Description:
    ##      The Unconfirmed-Event-Notification is used to notify a remote device that an event has
    ##      occurred.
    ## Unconfirmed-Event-Notification Structure:
    ##      - Process Identifier:           uint32                  -> Mandatory
    ##          + Process number in the receiving device for which this notification is intended
    ##      - Initiating Device Identifier: BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device
    ##      - Event Object Identifier:      BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object initiating the notification
    ##      - Time Stamp:                   BACnetTimestamp         -> Mandatory
    ##          + Current time as determined by clock in device issuing notification
    ##      - Notification Class:           uint32                  -> Mandatory
    ##          + Designates notification class of the event
    ##      - Priority:                     uint8                   -> Mandatory
    ##          + Priority of the event that has occurred (lower number = higher priority)
    ##      - Event Type                    uint32                  -> Mandatory
    ##          + Type of Event that has occurred
    ##      - Message Text                  string                  -> Optional
    ##          + Message to be logged or displayed
    ##      - Notify Type                   enum                    -> Mandatory
    ##          + BACnet Notify Type whether this notification is an event, alarm, or ack notification
    ##      - Ack Required:                 uint8                   -> Only if Notify Type is EVENT or ALARM
    ##          + Boolean parameter whether or not notification requires acknowledgment
    ##      - From State:                   uint32                  -> Only if Notify Type is EVENT or ALARM
    ##          + State of the object prior to occurrence of event that initiated notification
    ##      - To State:                     uint32                  -> Mandatory
    ##          + State of the object after occurrence of event that initiated notification
    ##      - Event Values:                 list                    -> Only if Notify Type is EVENT or ALARM
    ##          + Set of values relevant to the particular event
    ## Unconfirmed-Event-Notification Event Generation:
    ##      - process_identifier            -> Process Identifier
    ##      - initiating_object_type        -> Object Type from Initiating Device Identifier
    ##      - initiating_instance_number    -> Instance Number from Initiating Device Identifier
    ##      - event_object_type             -> Object Type from Event Object Identifier
    ##      - event_instance_number         -> Instance Number from Event Object Identifier
    ##      - notification_class            -> Notification Class
    ##      - priority                      -> Priority
    ##      - event_type                    -> Event Type
    ##      - message_text                  -> Message Text
    ##      - notify_type                   -> Notify Type
    ##      - ack_required                  -> ACK Required
    ##      - from_state                    -> From State
    ##      - to_state                      -> To State
    ## ------------------------------------------------------------------------------------------------
    function process_unconfirmed_event_notification(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_unconfirmed_event_notification )
            {
                BACnetObjectIdentifier initiating_identifier, event_identifier;

                uint32 process_identifier = UINT32_MAX, notification_class = UINT32_MAX,
                       event_type = UINT32_MAX, from_state = UINT32_MAX, to_state = UINT32_MAX;

                uint8 priority = UINT8_MAX, notify_type = UINT8_MAX, ack_required = UINT8_MAX;

                string message_text = "";

                for ( uint32 i = 0; i < ${tags}->size(); ++i ){
                    switch(${tags[i].tag_num}){
                        case 0:
                            process_identifier = get_unsigned(${tags[i].tag_data});
                            break;
                        case 1:
                            initiating_identifier = {${tags[i].tag_data}};
                            break;
                        case 2:
                            event_identifier = {${tags[i].tag_data}};
                            break;
                        case 4:
                            notification_class = get_unsigned(${tags[i].tag_data});
                            break;
                        case 5:
                            priority = ${tags[i].tag_data[0]};
                            break;
                        case 6:
                            event_type = get_unsigned(${tags[i].tag_data});
                            break;
                        case 7:
                            message_text = get_string(${tags[i].tag_data});
                            break;
                        case 8:
                            notify_type = ${tags[i].tag_data[0]};
                            break;
                        case 9:
                            ack_required = ${tags[i].tag_data[0]};
                            break;
                        case 10:
                            from_state = get_unsigned(${tags[i].tag_data});
                            break;
                        case 11:
                            to_state = get_unsigned(${tags[i].tag_data});
                            break;
                        default:
                            break;
                    }
                }

                zeek::BifEvent::enqueue_bacnet_unconfirmed_event_notification(connection()->zeek_analyzer(),
                                                                              connection()->zeek_analyzer()->Conn(),
                                                                              is_orig,
                                                                              process_identifier,
                                                                              initiating_identifier.object_type,
                                                                              initiating_identifier.instance_number,
                                                                              event_identifier.object_type,
                                                                              event_identifier.instance_number,
                                                                              notification_class,
                                                                              priority,
                                                                              event_type,
                                                                              zeek::make_intrusive<zeek::StringVal>(message_text),
                                                                              notify_type,
                                                                              ack_required,
                                                                              from_state,
                                                                              to_state);
            }
            return true;
        %}

    ## ------------------------------process_unconfirmed_private_transfer------------------------------
    ## Unconfirmed-Private-Transfer Description:
    ##      This service is used by a client BACnet user to invoke proprietary or non-standard
    ##      services in a remote device
    ## Unconfirmed-Private-Transfer Service Structure:
    ##      - Vendor ID:            uint32  -> Mandatory
    ##          + Vendor ID code for the type of vendor-proprietary service to be performed
    ##      - Service Number:       uint32  -> Mandatory
    ##          + Specify the desired service to be performed
    ##      - Service Parameters:   list    -> Optional
    ##          + Conveys additional parameters for services specified from vendor id and service
    ## Unconfirmed-Private-Transfer Event Generation:
    ##      - vendor_id         -> Vendor ID
    ##      - service_number    -> Service Number
    ## ------------------------------------------------------------------------------------------------
    function process_unconfirmed_private_transfer(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_unconfirmed_private_transfer )
            {
                uint32 vendor_id = get_unsigned(${tags[0].tag_data});
                uint32 service_number = get_unsigned(${tags[1].tag_data});
                zeek::BifEvent::enqueue_bacnet_unconfirmed_private_transfer(connection()->zeek_analyzer(),
                                                                            connection()->zeek_analyzer()->Conn(),
                                                                            is_orig,
                                                                            vendor_id,
                                                                            service_number);
            }
            return true;
        %}

    ## --------------------------------process_unconfirmed_text_message--------------------------------
    ## Unconfirmed-Text-Message Description:
    ##      The Unconfirmed Text Message
    ## Unconfirmed-Text-Message Structure:
    ##      - Text Message Source Device:   BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device initiating request
    ##      - Message Class:                uint32 | string         -> Optional
    ##          + Classification of the received message
    ##      - Message Priority:             enum                    -> Mandatory
    ##          + Indicate priority for message handling (NORMAL or URGENT)
    ##      - Message:                      string                  -> Mandatory
    ##          + Text Message
    ## Unconfirmed-Text-Message Event Generation:
    ##      - object_type       -> Object Type from Object Identifier
    ##      - instance_number   -> Instance Number from Object Identifier
    ##      - message_priority  -> Message Priority
    ##      - message           -> Message
    ## ------------------------------------------------------------------------------------------------
    function process_unconfirmed_text_message(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_unconfirmed_text_message )
            {
                uint8 i = 1;
                BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};

                if( ${tags[i].tag_num} == 1 ){
                    i += 1;
                }

                uint8 message_priority = ${tags[i].tag_data[0]};;
                string message = get_string(${tags[i+1].tag_data});

                zeek::BifEvent::enqueue_bacnet_unconfirmed_text_message(connection()->zeek_analyzer(),
                                                                        connection()->zeek_analyzer()->Conn(),
                                                                        is_orig,
                                                                        object_identifier.object_type,
                                                                        object_identifier.instance_number,
                                                                        message_priority,
                                                                        zeek::make_intrusive<zeek::StringVal>(message));
            }
            return true;
        %}

    ## ----------------------------------process_time_synchronization----------------------------------
    ## Time-Synchronization Description:
    ##      The Time-Synchronization service is to notify a remote device of the correct current time.
    ## Time-Synchronization Structure:
    ##      - Date:     BACnetDate  -> Mandatory
    ##          + Current date as determined by the clock in device issuing request
    ##      - Time:     BACnetTime  -> Mandatory
    ##          + Current time as determined by the clock in device issuing request
    ## Time-Synchronization Event Generation:
    ##      - year          -> Date - Year
    ##      - month         -> Date - Month
    ##      - day           -> Date - Day of Month
    ##      - day_of_week   -> Date - Day of Week
    ##      - hour          -> Time - Hour
    ##      - minute        -> Time - Minute
    ##      - second        -> Time - Second
    ##      - millisecond   -> Time - Millisecond
    ## ------------------------------------------------------------------------------------------------
    function process_time_synchronization(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_time_synchronization )
            {
                BACnetDate date = {${tags[0].tag_data}};
                BACnetTime time = {${tags[1].tag_data}};
                zeek::BifEvent::enqueue_bacnet_time_synchronization(connection()->zeek_analyzer(),
                                                                    connection()->zeek_analyzer()->Conn(),
                                                                    is_orig,
                                                                    date.year,
                                                                    date.month,
                                                                    date.day,
                                                                    date.day_of_week,
                                                                    time.hour,
                                                                    time.minute,
                                                                    time.second,
                                                                    time.millisecond);
            }
            return true;
        %}

    ## -----------------------------------------process_who_has----------------------------------------
    ## Who-Has Description:
    ##      The Who-Has service is to determine the device object identifier, the network address, or
    ##      both, of other BACnet devices that share the same internetwork.
    ## Who-Has Structure:
    ##      - Device Instance Range Low Limit:  uint32                  -> Optional (Mandatory if high limit exists)
    ##          + Along with Device Instance Range High Limit, defines devices qualified to respond
    ##            with an I-Have service request.
    ##      - Device Instance Range High Limit: uint32                  -> Optional (Mandatory if low limit exists)
    ##          + Along with Device Instance Range Low Limit, defines devices qualified to respond
    ##            with an I-Have service request.
    ##      - Object Identifier:                BACnetObjectIdentifier  -> Optional (Mandatory if Object Name is omitted)
    ##          + BACnet Object Identifier of object to be located
    ##      - Object Name:                      string                  -> Optional (Mandatory if Object Identifier is omitted)
    ##          + Name of the object to be located
    ## Who-Has Event Generation:
    ##      - low_limit         -> Device Instance Range Low Limit
    ##      - high_limit        -> Device Instance Range High Limit
    ##      - object_type       -> Object Type from Object Identifier
    ##      - instance_number   -> Instance Number from Object Identifier
    ##      - object_name       -> Object Name
    ## ------------------------------------------------------------------------------------------------
    function process_who_has(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_who_has )
            {
                BACnetObjectIdentifier object_identifier;
                uint32 low_limit = UINT32_MAX, high_limit = UINT32_MAX;
                string object_name = "";

                for ( uint32 i = 0; i < ${tags}->size(); ++i ){
                    switch(${tags[i].tag_num}){
                        case 0:
                            low_limit = get_unsigned(${tags[i].tag_data});
                            break;
                        case 1:
                            high_limit = get_unsigned(${tags[i].tag_data});
                            break;
                        case 2:
                            if ( ${tags[i].tag_length} == 4 )
                                object_identifier = {${tags[i].tag_data}};
                            break;
                        case 3:
                            object_name = get_string(${tags[i].tag_data});
                            break;
                        default:
                            break;
                    }
                }

                if (low_limit == UINT32_MAX)
                    high_limit = UINT32_MAX;

                if (high_limit == UINT32_MAX)
                    low_limit = UINT32_MAX;

                zeek::BifEvent::enqueue_bacnet_who_has(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       is_orig,
                                                       low_limit,
                                                       high_limit,
                                                       object_identifier.object_type,
                                                       object_identifier.instance_number,
                                                       zeek::make_intrusive<zeek::StringVal>(object_name));
            }
            return true;
        %}

    ## -----------------------------------------process_who_is-----------------------------------------
    ## Who-Is Description:
    ##      The Who-Is service is to determine the device object identifier, the network address, or
    ##      both, of other BACnet devices that share the same internetwork.
    ## Who-Is Structure:
    ##      - Device Instance Range Low Limit:      uint32  -> Optional (Mandatory if high limit exists)
    ##          + Along with Device Instance Range High Limit, defines devices qualified to respond
    ##            with an I-Have service request.
    ##      - Device Instance Range High Limit:     uint32  -> Optional (Mandatory if low limit exists)
    ##          + Along with Device Instance Range Low Limit, defines devices qualified to respond
    ##            with an I-Have service request.
    ## Who-Is Event Generation:
    ##      - low_limit     -> Device Instance Range Low Limit
    ##      - high_limit    -> Device Instance Range High Limit
    ## ------------------------------------------------------------------------------------------------
    function process_who_is(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_who_is )
            {
                uint32 low_limit =  UINT32_MAX, high_limit =  UINT32_MAX;
                if( ${tags}->size() > 1 )
                {
                    low_limit = get_unsigned(${tags[0].tag_data});
                    high_limit = get_unsigned(${tags[1].tag_data});
                }

                if (low_limit == 0 && high_limit == 0)
                {
                    low_limit = UINT32_MAX;
                    high_limit = UINT32_MAX;
                }

                zeek::BifEvent::enqueue_bacnet_who_is(connection()->zeek_analyzer(),
                                                      connection()->zeek_analyzer()->Conn(),
                                                      is_orig,
                                                      low_limit,
                                                      high_limit);
            }
            return true;
        %}

    ## --------------------------------process_utc_time_synchronization--------------------------------
    ## UTC-Time-Synchronization Description:
    ##      The UTC-Time-Synchronization service is to notify a remote device of the correct UTC.
    ## UTC-Time-Synchronization Structure:
    ##      - Date:     BACnetDate  -> Mandatory
    ##          + Current date as determined by the clock in device issuing request
    ##      - Time:     BACnetTime  -> Mandatory
    ##          + Current time as determined by the clock in device issuing request
    ## UTC-Time-Synchronization Event Generation:
    ##      - year          -> Date - Year
    ##      - month         -> Date - Month
    ##      - day           -> Date - Day of Month
    ##      - day_of_week   -> Date - Day of Week
    ##      - hour          -> Time - Hour
    ##      - minute        -> Time - Minute
    ##      - second        -> Time - Second
    ##      - millisecond   -> Time - Millisecond
    ## ------------------------------------------------------------------------------------------------
    function process_utc_time_synchronization(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_utc_time_synchronization )
            {
                BACnetDate date = {${tags[0].tag_data}};
                BACnetTime time = {${tags[1].tag_data}};

                zeek::BifEvent::enqueue_bacnet_utc_time_synchronization(connection()->zeek_analyzer(),
                                                                        connection()->zeek_analyzer()->Conn(),
                                                                        is_orig,
                                                                        date.year,
                                                                        date.month,
                                                                        date.day,
                                                                        date.day_of_week,
                                                                        time.hour,
                                                                        time.minute,
                                                                        time.second,
                                                                        time.millisecond);
            }
            return true;
        %}

    ## --------------------------------------process_write_group---------------------------------------
    ## Write-Group Description:
    ##      The Write-Group service is to facilitate the efficient distribution of values to a large
    ##      number of devices and objects
    ## Write-Group Structure:
    ##      - Group Number:     uint32  -> Mandatory
    ##          + Represents control group to affected by this request
    ##      - Write Priority:   uint8   -> Mandatory
    ##          + Priority for writing
    ##      - Change List:      list    -> Mandatory
    ##          + List of tuples representing changes to be written
    ##      - Inhibit Delay:    bool    -> Optional
    ##          + Specify whether or not execution delays should occur in change list
    ## Write-Group Event Generation:
    ##      - group_number      -> Group Number
    ##      - write_priority    -> Write Priority
    ## ------------------------------------------------------------------------------------------------
    function process_write_group(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_write_group )
            {
                uint32 group_number = get_unsigned(${tags[0].tag_data});
                uint8 write_priority = ${tags[1].tag_data[1]};

                zeek::BifEvent::enqueue_bacnet_write_group(connection()->zeek_analyzer(),
                                                           connection()->zeek_analyzer()->Conn(),
                                                           is_orig,
                                                           group_number,
                                                           write_priority);
            }
            return true;
        %}

    ## -------------------------process_unconfirmed_cov_notification-multiple--------------------------
    ## Unconfirmed-COV-Notification-Multiple Description:
    ##      The Unconfirmed-COV-Notification-Multiple service is used to notify subscribers about
    ##      changes to one or more properties of one or more objects
    ## Unconfirmed-COV-Notification-Multiple Structure:
    ##      - Subscriber Process Identifier:    uint32                          -> Mandatory
    ##          + Numerical Handle meaningful to the subscriber
    ##      - Initiating Device Identifier:     BACnetObjectIdentifier          -> Mandatory
    ##          + BACnet Object Identifier of device
    ##      - Time Remaining:                   uint32                          -> Mandatory
    ##          + Remaining lifetime of COV-multiple subscription in seconds
    ##      - Timestamp:                        BACnetTimestamp                 -> Optional
    ##          + Date and time of last change conveyed in the notification
    ##      - List of COV Notifications:        list of BACnetObjectIdentifier  -> Mandatory
    ##          + List of one or more COV Notifications
    ## Unconfirmed-COV-Notification-Multiple Event Generation:
    ##      - subscriber_id                 -> Subscriber Process Identifier
    ##      - initiating_object_type        -> Object Type from Initiating Device Identifier
    ##      - initiating_instance_number    -> Instance Number from Initiating Device Identifier
    ##      - time_remaining                -> Time Remaining
    ## ------------------------------------------------------------------------------------------------
    function process_unconfirmed_cov_notification_multiple(is_orig: bool, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_unconfirmed_cov_notification_multiple )
            {
                uint32 subscriber_identifier = get_unsigned(${tags[0].tag_data});
                BACnetObjectIdentifier initiating_identifier = {${tags[1].tag_data}};
                uint32 time_remaining = get_unsigned(${tags[2].tag_data});

                zeek::BifEvent::enqueue_bacnet_unconfirmed_cov_notification_multiple(connection()->zeek_analyzer(),
                                                                                     connection()->zeek_analyzer()->Conn(),
                                                                                     is_orig,
                                                                                     subscriber_identifier,
                                                                                     initiating_identifier.object_type,
                                                                                     initiating_identifier.instance_number,
                                                                                     time_remaining);
            }
            return true;
        %}

    ###################################################################################################
    ############################### END OF UNCONFIRMED SERVICE REQUESTS ###############################
    ###################################################################################################



    ###################################################################################################
    ################################### CONFIRMED SERVICE REQUESTS ####################################
    ###################################################################################################

    ## -----------------------------------process_acknowledge_alarm------------------------------------
    ## Acknowledge-Alarm Description:
    ##      The Acknowledge-Alarm service is used to acknowledge that a human operator has seen and
    ##      responded to an event notification.
    ## Acknowledge-Alarm Structure:
    ##      - Acknowledging Process Identifier: uint32                  -> Mandatory
    ##          + Process Identifier of acknowledging process
    ##      - Event Object Identifier:          BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of event notification
    ##      - Event State Acknowledged:         uint32                  -> Mandatory
    ##          + Matches 'To State' value from event notification
    ##      - Timestamp:                        BACnetTimestamp         -> Mandatory
    ##          + Matches 'Timestamp' value from event notification
    ##      - Acknowledgment Source:            string                  -> Mandatory
    ##          + Identity of the operator or process acknowledging the event notification
    ##      - Time of Acknowledgment:           BACnetTimestamp         -> Mandatory
    ##          + Time operator/process acknowledged the event notification
    ## Acknowledge-Alarm Event Generation:
    ##      - acknowledge_process_id    -> Acknowledging Process Identifier
    ##      - event_object_type         -> Object Type from Event Object Identifier Identifier
    ##      - event_instance_number     -> Instance Number from Event Object Identifier Identifier
    ##      - event_state               -> Event State
    ## ------------------------------------------------------------------------------------------------
    function process_acknowledge_alarm(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_acknowledge_alarm )
            {
                uint32 acknowledge_process_id = get_unsigned(${tags[0].tag_data});
                BACnetObjectIdentifier event_identifier = {${tags[1].tag_data}};
                uint32 event_state = get_unsigned(${tags[2].tag_data});

                zeek::BifEvent::enqueue_bacnet_acknowledge_alarm(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 is_orig,
                                                                 invoke_id,
                                                                 acknowledge_process_id,
                                                                 event_identifier.object_type,
                                                                 event_identifier.instance_number,
                                                                 event_state);
            }
            return true;
        %}

    ## -------------------------------process_confirmed_cov_notification-------------------------------
    ## Confirmed-COV-Notification Description:
    ##      The Confirmed-COV-Notification service is used to notify subscribers about changes that may
    ##      have occurred to the properties of a particular object
    ## Confirmed-COV-Notification Structure:
    ##      - Subscriber Process Identifier:    uint32                  -> Mandatory
    ##          + Numerical Handle meaningful to the subscriber
    ##      - Initiating Device Identifier:     BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device
    ##      - Monitored Object Identifier:      BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object that has changed
    ##      - Time Remaining:                   uint32                  -> Mandatory
    ##          + Remaining lifetime of the subscription in seconds
    ##      - List of Values:                   list                    -> Mandatory
    ##          + List of one or more property values
    ## Confirmed-COV-Notification Event Generation:
    ##      - subscriber_id                 -> Subscriber Process Identifier
    ##      - initiating_object_type        -> Object Type from Initiating Device Identifier
    ##      - initiating_instance_number    -> Instance Number from Initiating Device Identifier
    ##      - monitored_object_type         -> Object Type from Monitored Device Identifier
    ##      - monitored_instance_number     -> Instance Number from Monitored Device Identifier
    ##      - time_remaining                -> Time Remaining
    ## ------------------------------------------------------------------------------------------------
    function process_confirmed_cov_notification(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_confirmed_cov_notification )
            {
                uint32 subscriber_identifier = get_unsigned(${tags[0].tag_data});
                BACnetObjectIdentifier initiating_identifier = {${tags[1].tag_data}};
                BACnetObjectIdentifier monitored_identifier = {${tags[2].tag_data}};
                uint32 time_remaining = get_unsigned(${tags[3].tag_data});

                zeek::BifEvent::enqueue_bacnet_confirmed_cov_notification(connection()->zeek_analyzer(),
                                                                          connection()->zeek_analyzer()->Conn(),
                                                                          is_orig,
                                                                          invoke_id,
                                                                          subscriber_identifier,
                                                                          initiating_identifier.object_type,
                                                                          initiating_identifier.instance_number,
                                                                          monitored_identifier.object_type,
                                                                          monitored_identifier.instance_number,
                                                                          time_remaining);
            }
            return true;
        %}

    ## ------------------------------process_confirmed_event_notification------------------------------
    ## Confirmed-Event-Notification Description:
    ##      The Confirmed-Event-Notification service is used to notify a remote device that an event
    ##      has occurred.
    ## Confirmed-Event-Notification Structure:
    ##      - Process Identifier:           uint32                  -> Mandatory
    ##          + Process number in the receiving device for which this notification is intended
    ##      - Initiating Device Identifier: BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device
    ##      - Event Object Identifier:      BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object initiating the notification
    ##      - Time Stamp:                   BACnetTimestamp         -> Mandatory
    ##          + Current time as determined by clock in device issuing notification
    ##      - Notification Class:           uint32                  -> Mandatory
    ##          + Designates notification class of the event
    ##      - Priority:                     uint8                   -> Mandatory
    ##          + Priority of the event that has occurred (lower number = higher priority)
    ##      - Event Type                    uint32                  -> Mandatory
    ##          + Type of Event that has occurred
    ##      - Message Text                  string                  -> Optional
    ##          + Message to be logged or displayed
    ##      - Notify Type                   {EVENT, ALARM, ACK_NOTIFICATION} -> Mandatory
    ##          + BACnet Notify Type whether this notification is an event, alarm, or ack notification
    ##      - Ack Required:                 uint8                   -> Only if Notify Type is EVENT or ALARM
    ##          + Boolean parameter whether or not notification requires acknowledgment
    ##      - From State:                   uint32                  -> Only if Notify Type is EVENT or ALARM
    ##          + State of the object prior to occurrence of event that initiated notification
    ##      - To State:                     uint32                  -> Mandatory
    ##          + State of the object after occurrence of event that initiated notification
    ##      - Event Values:                 list                    -> Only if Notify Type is EVENT or ALARM
    ##          + Set of values relevant to the particular event
    ## Confirmed-Event-Notification Event Generation:
    ##      - process_identifier            -> Process Identifier
    ##      - initiating_object_type        -> Object Type from Initiating Device Identifier
    ##      - initiating_instance_number    -> Instance Number from Initiating Device Identifier
    ##      - event_object_type             -> Object Type from Event Object Identifier
    ##      - event_instance_number         -> Instance Number from Event Object Identifier
    ##      - notification_class            -> Notification Class
    ##      - priority                      -> Priority
    ##      - event_type                    -> Event Type
    ##      - message_text                  -> Message Text
    ##      - notify_type                   -> Notify Type
    ##      - ack_required                  -> ACK Required
    ##      - from_state                    -> From State
    ##      - to_state                      -> To State
    ## ------------------------------------------------------------------------------------------------
    function process_confirmed_event_notification(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_confirmed_event_notification )
            {
                BACnetObjectIdentifier initiating_identifier, event_identifier;

                uint32 process_identifier = UINT32_MAX, notification_class = UINT32_MAX,
                       event_type = UINT32_MAX, from_state = UINT32_MAX, to_state = UINT32_MAX;

                uint8 priority = UINT8_MAX, notify_type = UINT8_MAX, ack_required = UINT8_MAX;

                string message_text = "";

                for ( uint32 i = 0; i < ${tags}->size(); ++i ){
                    switch(${tags[i].tag_num}){
                        case 0:
                            process_identifier = get_unsigned(${tags[i].tag_data});
                            break;
                        case 1:
                            initiating_identifier = {${tags[i].tag_data}};
                            break;
                        case 2:
                            event_identifier = {${tags[i].tag_data}};
                            break;
                        case 4:
                            notification_class = get_unsigned(${tags[i].tag_data});
                            break;
                        case 5:
                            priority = ${tags[i].tag_data[0]};
                            break;
                        case 6:
                            event_type = get_unsigned(${tags[i].tag_data});
                            break;
                        case 7:
                            message_text = get_string(${tags[i].tag_data});
                            break;
                        case 8:
                            notify_type = ${tags[i].tag_data[0]};
                            break;
                        case 9:
                            ack_required = ${tags[i].tag_data[0]};
                            break;
                        case 10:
                            from_state = get_unsigned(${tags[i].tag_data});
                            break;
                        case 11:
                            to_state = get_unsigned(${tags[i].tag_data});
                            break;
                        default:
                            break;
                    }
                }

                zeek::BifEvent::enqueue_bacnet_confirmed_event_notification(connection()->zeek_analyzer(),
                                                                            connection()->zeek_analyzer()->Conn(),
                                                                            is_orig,
                                                                            invoke_id,
                                                                            process_identifier,
                                                                            initiating_identifier.object_type,
                                                                            initiating_identifier.instance_number,
                                                                            event_identifier.object_type,
                                                                            event_identifier.instance_number,
                                                                            notification_class,
                                                                            priority,
                                                                            event_type,
                                                                            zeek::make_intrusive<zeek::StringVal>(message_text),
                                                                            notify_type,
                                                                            ack_required,
                                                                            from_state,
                                                                            to_state);
            }
            return true;
        %}

    ## -----------------------------------process_get_alarm_summary------------------------------------
    ## Get-Alarm-Summary Description:
    ##      DEPRECATED.
    ##      The Get-Alarm-Summary service is used by client BACnet user to obtain a summary of alarms
    ## Get-Alarm-Summary Structure:
    ##      - N/A
    ## Get-Alarm-Summary Event Generation:
    ##      - N/A - Deprecated
    ## ------------------------------------------------------------------------------------------------
    function process_get_alarm_summary(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_get_alarm_summary )
            {
                zeek::BifEvent::enqueue_bacnet_get_alarm_summary(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 is_orig,
                                                                 invoke_id);
            }
            return true;
        %}

    ## ---------------------------------process_get_enrollment_summary---------------------------------
    ## Get-Enrollment-Summary Description:
    ##      DEPRECATED.
    ##      The Get-Enrollment-Summary service is used by client BACnet user to obtain a summary of
    ##      event-initiating objects
    ## Get-Enrollment-Summary Structure:
    ##      - N/A
    ## Get-Enrollment-Summary Event Generation:
    ##      - N/A - Deprecated
    ## ------------------------------------------------------------------------------------------------
    function process_get_enrollment_summary(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_get_enrollment_summary )
            {
                zeek::BifEvent::enqueue_bacnet_get_enrollment_summary(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      is_orig,
                                                                      invoke_id);
            }
            return true;
        %}

    ## -------------------------------------process_subscribe_cov--------------------------------------
    ##  Subscribe-COV Description:
    ##      The Subscribe-COV service is used to subscribe for the receipt of notification of changes
    ##      that may occur to the properties of a particular object
    ##  Subscribe-COV Structure:
    ##      - Subscriber Process Identifier:    uint32                  -> Mandatory
    ##          + Numerical handle meaningful to the subscriber
    ##      - Monitored Object Identifier:      BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier for which subscription is desired
    ##      - Issue Confirmed Notifications:    bool                    -> Optional
    ##          + Whether COV server shall issue Confirmed-COV-Notifications (TRUE) or
    ##            Unconfirmed-COV-Notification (FALSE) when changes occur
    ##      - Lifetime:                         uint32                  -> Optional
    ##          + Desired lifetime of the subscription in seconds
    ##  Subscribe-COV Event Generation:
    ##      - subscriber_process_identifier ->  Subscriber Process Identifier
    ##      - monitored_identifier          ->  Object Type from Monitored Object Identifier
    ##      - monitored_instance_number     ->  Instance Number from Monitored Object Identifier
    ##      - issue_confirmed               ->  Issue Confirmed Notification
    ##      - lifetime                      ->  Lifetime
    ## ------------------------------------------------------------------------------------------------
    function process_subscribe_cov(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_subscribe_cov )
            {
                uint32 subscriber_process_identifier = get_unsigned(${tags[0].tag_data});
                BACnetObjectIdentifier monitored_identifier = {${tags[1].tag_data}};
                uint32 lifetime = UINT32_MAX;
                uint8 issue_confirmed = UINT8_MAX;

                for ( uint32 i = 2; i < ${tags}->size(); ++i ){
                    switch(${tags[i].tag_num}){
                        case 2:
                            issue_confirmed = ${tags[i].tag_data[0]};
                            break;
                        case 3:
                            lifetime = get_unsigned(${tags[i].tag_data});
                            break;
                        default:
                            break;
                    }
                }

                zeek::BifEvent::enqueue_bacnet_subscribe_cov(connection()->zeek_analyzer(),
                                                             connection()->zeek_analyzer()->Conn(),
                                                             is_orig,
                                                             invoke_id,
                                                             subscriber_process_identifier,
                                                             monitored_identifier.object_type,
                                                             monitored_identifier.instance_number,
                                                             issue_confirmed,
                                                             lifetime);
            }
            return true;
        %}

    ## ------------------------------------process_atomic_read_file------------------------------------
    ##  Atomic-Read-File Description:
    ##      The Atomic-Read-File service is used by a client BACnet user to perform an open-read-close
    ##      operation on the contents of the specified file. The file may be accessed as records or as
    ##      a stream of octets
    ##  Atomic-Read-File Structure:
    ##      - File Identifier:  BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of the File object that identifies the file to be read
    ##      - Stream Access:    See below               -> Optional (Mandatory if Record Access does not exist)
    ##          + Stream-oriented file access is required. Contains parameters below:
    ##              - File Start Position:          uint32  -> Mandatory if Stream Access exists
    ##              - Requested Octet Count:        uint32  -> Mandatory if Stream Access exists
    ##      - Record Access:    See below               -> Optional (Mandatory if Stream Access does not exist)
    ##          + Record-oriented file access is required. Contains parameters below:
    ##              - File Start Record:            uint32  -> Mandatory if Record Access exists
    ##              - Requested Record Count:       uint32  -> Mandatory if Record Access exists
    ##  Atomic-Read-File Event Generation:
    ##      - file_object_type      -> Object Type from File Identifier
    ##      - file_instance_number  -> Instance Number from FileIdentifier
    ##      - access_type           -> Stream Access or Record Access
    ##      - file_start            -> File Start Position/File Start Record
    ##      - requested_count       -> Requested Octet Count/Requested Record Count
    ## ------------------------------------------------------------------------------------------------
    function process_atomic_read_file(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_atomic_read_file )
            {
                BACnetObjectIdentifier file_identifier = {${tags[0].tag_data}};
                string access_type;
                if(${tags[1].tag_num} == 0)
                    access_type = "Stream";
                else
                    access_type = "Record";

                uint32 file_start = get_unsigned(${tags[2].tag_data});
                uint32 requested_count = get_unsigned(${tags[3].tag_data});

                zeek::BifEvent::enqueue_bacnet_atomic_read_file(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                is_orig,
                                                                invoke_id,
                                                                file_identifier.object_type,
                                                                file_identifier.instance_number,
                                                                zeek::make_intrusive<zeek::StringVal>(access_type),
                                                                file_start,
                                                                requested_count);
            }
            return true;
        %}

    ## -----------------------------------process_atomic_write_file------------------------------------
    ##  Atomic-Write-File Description:
    ##      The Atomic-Write-File service is used by a client BACnet user to perform an
    ##      open-write-close operation of an octet string into a specified position or a list of octet
    ##      strings into a specified group of records in a file.
    ##  Atomic-Write-File Structure:
    ##      - File Identifier:  BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of the File object that identifies the file to be written
    ##      - Stream Access:    See below               -> Optional (Mandatory if Record Access does not exist)
    ##          + Stream-oriented file access is required. Contains parameters below:
    ##              - File Start Position:          uint32  -> Mandatory if Stream Access exists
    ##              - File Data:                    string  -> Mandatory if Stream Access exists
    ##      - Record Access:    See below               -> Optional (Mandatory if Stream Access does not exist)
    ##          + Record-oriented file access is required. Contains parameters below:
    ##              - File Start Record:            uint32  -> Mandatory if Record Access exists
    ##              - Record Count:                 uint32  -> Mandatory if Record Access exists
    ##              - Record Data:                  string  -> Mandatory if Record Access exists
    ##  Atomic-Write-File Event Generation:
    ##      - file_object_type      -> Object Type from File Identifier
    ##      - file_instance_number  -> Instance Number from FileIdentifier
    ##      - access_type           -> Stream Access or Record Access
    ##      - file_start            -> File Start Position/File Start Record
    ##      - requested_count       -> Record Count
    ##      - data_to_write         -> File Data/Record Data
    ## ------------------------------------------------------------------------------------------------
    function process_atomic_write_file(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            uint32 record_count = UINT32_MAX;
            string access_type;
            string data_to_write;

            BACnetObjectIdentifier file_identifier = {${tags[0].tag_data}};
            uint32 file_start = get_unsigned(${tags[2].tag_data});

            if(${tags[1].tag_num} == 0){
                access_type = "Stream";
                data_to_write = get_string2(${tags[3].tag_data});

                zeek::file_mgr->DataIn(${tags[3].tag_data}.begin(),
                                       ${tags[3].tag_length},
                                       file_start,
                                       connection()->zeek_analyzer()->GetAnalyzerTag(),
                                       connection()->zeek_analyzer()->Conn(),
                                       is_orig);
            }
            else{
                access_type = "Record";
                record_count = get_unsigned(${tags[3].tag_data});
                data_to_write = get_string2(${tags[4].tag_data});
            }

            if ( ::bacnet_atomic_write_file )
            {
                zeek::BifEvent::enqueue_bacnet_atomic_write_file(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 is_orig,
                                                                 invoke_id,
                                                                 file_identifier.object_type,
                                                                 file_identifier.instance_number,
                                                                 zeek::make_intrusive<zeek::StringVal>(access_type),
                                                                 file_start,
                                                                 record_count,
                                                                 zeek::make_intrusive<zeek::StringVal>(data_to_write));

            }
            return true;
        %}

    ## ------------------------------------process_add_list_element------------------------------------
    ##  Add-List-Element Description:
    ##      The Add-List-Element service is used by a client BACnet user to add one or more elements
    ##      to an object property that is a list
    ##  Add-List-Element Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object whose property is to be modified
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be modified
    ##      - Property Array Index: uint32                  -> Only if Property Identifier is of type datatype array
    ##          + Indicates array index of the element of the referenced property to be modified
    ##      - List of Elements:     list                    -> Mandatory
    ##          + Specifies one or more elements to be added to the property
    ##  Add-List-Element Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ## ------------------------------------------------------------------------------------------------
    function process_add_list_element(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_add_list_element )
            {
                BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                uint32 property_identifier = get_unsigned(${tags[1].tag_data});
                uint32 property_array_index = UINT32_MAX;

                if(${tags}->size() > 2)
                    property_array_index = get_unsigned(${tags[2].tag_data});

                zeek::BifEvent::enqueue_bacnet_add_list_element(connection()->zeek_analyzer(),
                                                                connection()->zeek_analyzer()->Conn(),
                                                                is_orig,
                                                                invoke_id,
                                                                object_identifier.object_type,
                                                                object_identifier.instance_number,
                                                                property_identifier,
                                                                property_array_index);
            }
            return true;
        %}

    ## ----------------------------------process_remove_list_element-----------------------------------
    ##  Remove-List-Element Description:
    ##      The Remove-List-Element service is used by a client BACnet-user to remove one or more
    ##      elements to an object property that is a list. If element is itself a list, the entire
    ##      list shall be removed.
    ##  Remove-List-Element Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of object whose property is to be modified
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be modified
    ##      - Property Array Index: uint32                  -> Only if Property Identifier is of type
    ##                                                         datatype array
    ##          + Indicates array index of the element of the referenced property to be modified
    ##      - List of Elements:     list                    -> Mandatory
    ##          + Specifies one or more elements to be removed to the property
    ##  Remove-List-Element Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ## ------------------------------------------------------------------------------------------------
    function process_remove_list_element(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_remove_list_element )
            {
                BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                uint32 property_identifier = get_unsigned(${tags[1].tag_data});
                uint32 property_array_index = UINT32_MAX;

                if(${tags}->size() > 2)
                    property_array_index = get_unsigned(${tags[2].tag_data});


                zeek::BifEvent::enqueue_bacnet_remove_list_element(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   is_orig,
                                                                   invoke_id,
                                                                   object_identifier.object_type,
                                                                   object_identifier.instance_number,
                                                                   property_identifier,
                                                                   property_array_index);
            }
            return true;
        %}

    ## -------------------------------------process_create_object--------------------------------------
    ##  Create-Object Description:
    ##      The Create-Object service is used by a client BACnet-user to create a new instance of an
    ##      object
    ##  Create-Object Structure:
    ##      - Object Specifier:         object_type | object_identifier -> Mandatory
    ##          + Information about the type of object that is to be created
    ##      - List of Initial Values:   list of BACnetPropertyValues    -> Optional
    ##          + List of values used to initialize the values of specified property of newly created
    ##            object
    ## ------------------------------------------------------------------------------------------------
    function process_create_object(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_create_object )
            {
                zeek::BifEvent::enqueue_bacnet_create_object(connection()->zeek_analyzer(),
                                                             connection()->zeek_analyzer()->Conn(),
                                                             is_orig,
                                                             invoke_id);
            }
            return true;
        %}

    ## -------------------------------------process_delete_object--------------------------------------
    ##  Delete-Object Description:
    ##      The Delete-Object service is used by a client BACnet-user to delete an existing object
    ##  Delete-Object Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + Specifies the object that is to be deleted
    ##  Delete-Object Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_delete_object(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_delete_object )
            {
                BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                zeek::BifEvent::enqueue_bacnet_delete_object(connection()->zeek_analyzer(),
                                                             connection()->zeek_analyzer()->Conn(),
                                                             is_orig,
                                                             invoke_id,
                                                             object_identifier.object_type,
                                                             object_identifier.instance_number);
            }
            return true;
        %}

    ## -------------------------------------process_read_property--------------------------------------
    ##  Read-Property Description:
    ##      The Read-Property service is used by a client BACnet-user to request the value of one
    ##      property of one BACnet Object
    ##  Read-Property Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + Object whose property is to be read
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be read
    ##      - Property Array Index: uint32                  -> Optional
    ##          + Array index of the element of the property to be returned
    ##  Read-Property Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ## ------------------------------------------------------------------------------------------------
    function process_read_property(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_read_property )
            {
                if ( ${tags}->size() >= 2 )
                {
                    BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                    uint32 property_identifier = get_unsigned(${tags[1].tag_data});
                    uint32 property_array_index = UINT32_MAX;

                    if( ${tags}->size() > 2 )
                        property_array_index = get_unsigned(${tags[2].tag_data});

                    zeek::BifEvent::enqueue_bacnet_read_property(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 is_orig,
                                                                 invoke_id,
                                                                 zeek::make_intrusive<zeek::StringVal>("read-property-request"),
                                                                 object_identifier.object_type,
                                                                 object_identifier.instance_number,
                                                                 property_identifier,
                                                                 property_array_index);
                }
            }
            return true;
        %}

    ## ---------------------------------process_read_property_multiple---------------------------------
    ##  Read-Property-Multiple Description:
    ##      The Read-Property service is used by a client BACnet-user to request the values of one or
    ##      more specified properties of one or more BACnet objects
    ##  Read-Property-Multiple Structure:
    ##      - List of Read Access Specifications:   See below   -> Mandatory
    ##          + List of one or more read access specifications:
    ##              - Object Identifier:            BACnetObjectIdentifier          -> Mandatory
    ##              - List of Property References:  List of BACnetPropertyReference -> Mandatory
    ## ------------------------------------------------------------------------------------------------
    function process_read_property_multiple(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_read_property )
            {
                for ( uint32 x = 0; x < ${tags}->size(); ++x )
                {
                    BACnetObjectIdentifier object_identifier = {${tags[x].tag_data}};
                    x += 1;
                    for ( uint32 i = x; i < ${tags}->size(); ++i )
                    {
                        if(${tags[i].named_tag} == OPENING)
                        {
                            continue;
                        }
                        else if(${tags[i].named_tag} == CLOSING)
                        {
                            x = i;
                            break;
                        }
                        else
                        {
                            zeek::BifEvent::enqueue_bacnet_read_property(connection()->zeek_analyzer(),
                                                                         connection()->zeek_analyzer()->Conn(),
                                                                         is_orig,
                                                                         invoke_id,
                                                                         zeek::make_intrusive<zeek::StringVal>("read-property-multiple-request"),
                                                                         object_identifier.object_type,
                                                                         object_identifier.instance_number,
                                                                         get_unsigned(${tags[i].tag_data}),
                                                                         UINT32_MAX);
                        }
                    }
                }
            }
            return true;
        %}

    ## -------------------------------------process_write_property-------------------------------------
    ##  Write-Property Description:
    ##      The Write-Property service is used by a client BACnet-user to modify the value of a single
    ##      specified property of a BACnet object
    ##  Write-Property Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + Object whose property is to be modified
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be modified
    ##      - Property Array Index: uint32                  -> Optional
    ##          + Array index of the element of the property to be modified
    ##      - Property Value:       Variable                -> Mandatory
    ##          + Value of property to be written
    ##      - Priority:             uint8                   -> Optional
    ##          + Priority assigned to this write operation
    ##      - Property Value:       string                  -> Mandatory
    ##          + Value of property to be written
    ##  Write-Property Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ##      - priority                      ->  Priority
    ##      - property_value                ->  Property Value
    ## ------------------------------------------------------------------------------------------------
    function process_write_property(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_write_property )
            {
                if ( ${tags}->size() > 2 )
                {
                    BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                    uint32 property_identifier = get_unsigned(${tags[1].tag_data});
                    uint32 property_array_index = UINT32_MAX;
                    uint8 priority = UINT8_MAX;
                    string property_value = "";

                    int8 first = 1;
                    
                    for ( uint32 i = 2; i < ${tags}->size(); ++i )
                    {
                        switch(${tags[i].tag_num})
                        {
                            case 2:
                                property_array_index = get_unsigned(${tags[i].tag_data});
                                break;
                            case 3:
                                if ( first == 1 )
                                {
                                    property_value = parse_tag(${tags[i+1].tag_num},${tags[i+1].tag_class},${tags[i+1].tag_data},${tags[i+1].tag_length},${tags[i+1].tag_length_a});
                                    first = 0;
                                }
                                break;
                            case 4:
                                priority = ${tags[i].tag_data[0]};
                            default:
                                break;
                        }
                    }

                    zeek::BifEvent::enqueue_bacnet_write_property(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  is_orig,
                                                                  invoke_id,
                                                                  object_identifier.object_type,
                                                                  object_identifier.instance_number,
                                                                  property_identifier,
                                                                  property_array_index,
                                                                  priority,
                                                                  zeek::make_intrusive<zeek::StringVal>(property_value));
                }
            }
            return true;
        %}


    ## --------------------------------process_write_property_multiple---------------------------------
    ##  Write-Property-Multiple Description:
    ##      The Write-Property service is used by a client BACnet-user to modify the value of one or
    ##      more specified properties of a BACnet object.
    ##  Write-Property-Multiple Structure:
    ##      - List of Write Access Specifications:   See below   -> Mandatory
    ##          + List of one or more write access specifications:
    ##              - Object Identifier:            BACnetObjectIdentifier  -> Mandatory
    ##              - List of Properties:           See below               -> Mandatory
    ##                  + Property Identifier:      BACnetPropertyIdentifier    -> Mandatory
    ##                  + Property Array Index:     uint32                      -> Optional
    ##                  + Property Value:           stinrg                      -> Mandatory
    ##                  + Priority:                 uint8                       -> Optional
    ## ------------------------------------------------------------------------------------------------
    function process_write_property_multiple(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_write_property_multiple )
            {
                zeek::BifEvent::enqueue_bacnet_write_property_multiple(connection()->zeek_analyzer(),
                                                                       connection()->zeek_analyzer()->Conn(),
                                                                       is_orig,
                                                                       invoke_id);
            }
            return true;
        %}

    ## ------------------------------process_device_communication_control------------------------------
    ##  Device-Communication-Control Description:
    ##      The Device-Communication-Control service is used by a client BACnet-user to instruct a
    ##      remote device to stop initiating and optionally to stop responding to all APDUs.
    ##  Device-Communication-Control Structure:
    ##      - Time Duration:    uint16  -> Optional
    ##          + Number of minutes remote device shall ignore APDUs
    ##      - Enable/Disable:   enum    -> Mandatory
    ##          + Whether responding BACnet-user is to enable all, disable initiation, or disable all
    ##            communications
    ##      - Password:         string  -> Optional
    ##          + Password
    ##  Device-Communication-Control Event Generation:
    ##      - time_duration     ->  Time Duration
    ##      - enable_disable    ->  Enable/Disable
    ##      - password          ->  Password String
    ## ------------------------------------------------------------------------------------------------
    function process_device_communication_control(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_device_communication_control )
            {
                uint32 time_duration = UINT32_MAX;
                uint8 enable_disable = UINT8_MAX;
                string password = "";
                for ( uint32 i = 0; i < ${tags}->size(); ++i )
                {
                    switch(${tags[i].tag_num})
                    {
                        case 0:
                            time_duration = get_unsigned(${tags[i].tag_data});
                            if (time_duration == 0)
                                time_duration = UINT32_MAX;
                            break;
                        case 1:
                            enable_disable = ${tags[i].tag_data[0]};
                            break;
                        case 2:
                            password = get_string(${tags[i].tag_data});
                            break;
                        default:
                            break;
                    }
                }

                zeek::BifEvent::enqueue_bacnet_device_communication_control(connection()->zeek_analyzer(),
                                                                            connection()->zeek_analyzer()->Conn(),
                                                                            is_orig,
                                                                            invoke_id,
                                                                            time_duration,
                                                                            enable_disable,
                                                                            zeek::make_intrusive<zeek::StringVal>(password));
            }
            return true;
        %}

    ## -------------------------------process_confirmed_private_transfer-------------------------------
    ##  Confirmed-Private-Transfer Description:
    ##      The Confirmed-Private-Transfer service
    ##  Confirmed-Private-Transfer Structure:
    ##      - Vendor ID:            uint32  -> Mandatory
    ##          + Vendor ID code for the "type of vendor-proprietary service" to be performed
    ##      - Service Number:       uint32  -> Mandatory
    ##          + Specify the desired service to be performed
    ##      - Service Parameters:   list    -> Optional
    ##          + Conveys additional parameters for services specified from Vendor Id and Service Number
    ##  Confirmed-Private-Transfer Event Generation:
    ##      - vendor_id             -> Vendor ID
    ##      - service_number        -> Service Number
    ## ------------------------------------------------------------------------------------------------
    function process_confirmed_private_transfer(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_confirmed_private_transfer )
            {
                uint32 vendor_id = get_unsigned(${tags[0].tag_data});
                uint32 service_number = get_unsigned(${tags[1].tag_data});
                zeek::BifEvent::enqueue_bacnet_confirmed_private_transfer(connection()->zeek_analyzer(),
                                                                          connection()->zeek_analyzer()->Conn(),
                                                                          is_orig,
                                                                          invoke_id,
                                                                          vendor_id,
                                                                          service_number);
            }
            return true;
        %}


    ## ---------------------------------process_confirmed_text_message---------------------------------
    ##  Confirmed-Text-Message Description:
    ##      The Confirmed-Text-Message service
    ##  Confirmed-Text-Message Structure:
    ##      - Text Message Source Device:   BACnetObjectIdentifier  -> Mandatory
    ##          + BACnet Object Identifier of device initiating request
    ##      - Message Class:                uint32 | string         -> Optional
    ##          + Classification of the received message
    ##      - Message Priority:             enum                    -> Mandatory
    ##          + Indicate priority for message handling (NORMAL or URGENT)
    ##      - Message:                      string                  -> Mandatory
    ##          + Text Message
    ##  Confirmed-Text-Message Event Generation:
    ##      - object_type       -> Object Type from Object Identifier
    ##      - instance_number   -> Instance Number from Object Identifier
    ##      - message_priority  -> Message Priority
    ##      - message           -> Message
    ## ------------------------------------------------------------------------------------------------
    function process_confirmed_text_message(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_confirmed_text_message )
            {
                uint8 i = 1;
                BACnetObjectIdentifier object_identifier = {${tags[i].tag_data}};

                if( ${tags[i].tag_num} == 1 )
                    i += 1;

                uint8 message_priority = ${tags[i].tag_data[0]};;
                string message = get_string(${tags[i+1].tag_data});

                zeek::BifEvent::enqueue_bacnet_confirmed_text_message(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      is_orig,
                                                                      invoke_id,
                                                                      object_identifier.object_type,
                                                                      object_identifier.instance_number,
                                                                      message_priority,
                                                                      zeek::make_intrusive<zeek::StringVal>(message));
            }
            return true;
        %}

    ## ----------------------------------process_reinitialize_device----------------------------------
    ##  Reinitialize-Device Description:
    ##      The Reinitialize-Device service is used by a client BACnet user to instruct a remote
    ##      device to reboot itself, reset itself, or control reset/backup procedures
    ##  Reinitialize-Device Structure:
    ##      - Reinitialized State of Device:    enum    -> Mandatory
    ##          + Desired state of the device after its reinitialization
    ##      - Password:                         string  -> Optional
    ##          + Password
    ##  Reinitialize-Device Event Generation:
    ##      - reinitialized_state   -> Reinitialized State of Device
    ##      - password              -> Password String
    ## ------------------------------------------------------------------------------------------------
    function process_reinitialize_device(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_reinitialize_device )
            {
                string password = "";
                uint8 reinitialized_state = ${tags[0].tag_data[0]};

                if(${tags}->size() > 1)
                    password = get_string(${tags[1].tag_data});

                zeek::BifEvent::enqueue_bacnet_reinitialize_device(connection()->zeek_analyzer(),
                                                                   connection()->zeek_analyzer()->Conn(),
                                                                   is_orig,
                                                                   invoke_id,
                                                                   reinitialized_state,
                                                                   zeek::make_intrusive<zeek::StringVal>(password));
            }
            return true;
        %}

    ## ----------------------------------------process_vt_open-----------------------------------------
    ##  VT-Open Description:
    ##      The VT-Open service is used to establish a VT-session with a peer VT-user
    ##  VT-Open Structure:
    ##      - VT-Class:                     enum    -> Mandatory
    ##          + Name of desired class of session to be established
    ##      - Local VT Session Identifier:  uint8   -> Mandatory
    ##          + Unique VT-session in the requesting VT-user
    ##  VT-Open Event Generation:
    ##      - vt_class      -> VT-Class
    ##      - local_vt_id   -> Local VT Session Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_vt_open(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_vt_open )
            {
                uint8 vt_class = ${tags[0].tag_data[0]};
                uint8 local_vt_id = ${tags[1].tag_data[0]};

                zeek::BifEvent::enqueue_bacnet_vt_open(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       is_orig,
                                                       invoke_id,
                                                       vt_class,
                                                       local_vt_id);
            }
            return true;
        %}

    ## ----------------------------------------process_vt_close----------------------------------------
    ##  VT-Close Description:
    ##      The VT-Close service is used to terminate a previously established VT-session
    ##  VT-Close Structure:
    ##      - Remote VT Session Identifier:     uint8   -> Mandatory
    ##          + Remote VT Session Identifier to terminate
    ##  VT-Close Event Generation:
    ##      - remote_vt_id  -> Remote VT Session Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_vt_close(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_vt_close )
            {
                uint8 remote_vt_id = ${tags[0].tag_data[0]};
                zeek::BifEvent::enqueue_bacnet_vt_close(connection()->zeek_analyzer(),
                                                        connection()->zeek_analyzer()->Conn(),
                                                        is_orig,
                                                        invoke_id,
                                                        remote_vt_id);
            }
            return true;
        %}

    ## ----------------------------------------process_vt_data-----------------------------------------
    ##  VT-Data Description:
    ##      The VT-Data service
    ##  VT-Data Structure:
    ##      - VT-session Identifier:    uint8   -> Mandatory
    ##          + Particular VT-session to which data will be sent
    ##      - VT-new Data:              string  -> Mandatory
    ##          + Data to be sent
    ##      - VT-data Flag:             uint8   -> Mandatory
    ##          + Expected sequence to VT-Data requests
    ##  VT-Data Event Generation:
    ##      - vt_session_id -> VT-session Identifier
    ##      - vt_data       -> VT-new Data
    ##      - vt_flag       -> VT-data Flag
    ## ------------------------------------------------------------------------------------------------
    function process_vt_data(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_vt_data )
            {
                uint8 vt_session_id = ${tags[0].tag_data[0]};
                string vt_data = get_string(${tags[1].tag_data});
                uint8 vt_flag = ${tags[2].tag_data[0]};

                zeek::BifEvent::enqueue_bacnet_vt_data(connection()->zeek_analyzer(),
                                                       connection()->zeek_analyzer()->Conn(),
                                                       is_orig,
                                                       invoke_id,
                                                       vt_session_id,
                                                       zeek::make_intrusive<zeek::StringVal>(vt_data),
                                                       vt_flag);
            }
            return true;
        %}

    ## ---------------------------------------process_read_range---------------------------------------
    ##  Read-Range Description:
    ##      The Read-Range service is used by a client BACnet-user to read a specific range of data
    ##      items representing a subset of data available within a specified object property
    ##  Read-Range Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  ->  Mandatory
    ##          + Object and property to be read
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be read and returned
    ##      - Property Array Index: uint32                  ->  Optional
    ##          + Array index of the element of the property to be returned
    ##  Read-Range Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ## ------------------------------------------------------------------------------------------------
    function process_read_range(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_read_range )
            {
                if ( ${tags}->size() >= 2 )
                {
                    BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                    uint32 property_identifier = get_unsigned(${tags[1].tag_data});
                    uint32 property_array_index = UINT32_MAX;

                    if(${tags}->size() > 2)
                        property_array_index = get_unsigned(${tags[2].tag_data});

                    zeek::BifEvent::enqueue_bacnet_read_range(connection()->zeek_analyzer(),
                                                              connection()->zeek_analyzer()->Conn(),
                                                              is_orig,
                                                              invoke_id,
                                                              object_identifier.object_type,
                                                              object_identifier.instance_number,
                                                              property_identifier,
                                                              property_array_index);
                }
            }
            return true;
        %}

    ## ---------------------------------process_life_safety_operation----------------------------------
    ##  Life-Safety-Operation Description:
    ##      The Life-Safety-Operation service is intended for use in an emergency to provide a way for
    ##      conveying specific instructions from a human operator
    ##  Life-Safety-Operation Structure:
    ##      - Requesting Process Identifier:    uint32                  -> Mandatory
    ##          + Unique number identifying process which initiated the service request
    ##      - Requesting Source:                string                  -> Mandatory
    ##          + Identity of human operator that initiated request
    ##      - Request:                          enum                    -> Mandatory
    ##          + Requested Operation
    ##      - Object Identifier:                BACnetObjectIdentifier  -> Optional
    ##          + BACnetObjectIdentifier of device
    ##  Life-Safety-Operation Event Generation:
    ##      - requesting_id             -> Requesting Process Identifier
    ##      - requesting_source         -> Requesting Source
    ##      - request                   -> Request
    ##      - object_type               -> Object Type from Object Identifier
    ##      - object_instance_number    -> Instance Number from Object Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_life_safety_operation(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_life_safety_operation )
            {
                BACnetObjectIdentifier object_identifier;

                uint32 requesting_id = get_unsigned(${tags[0].tag_data});
                string requesting_source = get_string(${tags[1].tag_data});
                uint8 request = ${tags[2].tag_data[0]};

                if(${tags}->size() > 3)
                    object_identifier = {${tags[3].tag_data}};

                zeek::BifEvent::enqueue_bacnet_life_safety_operation(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     is_orig,
                                                                     invoke_id,
                                                                     requesting_id,
                                                                     zeek::make_intrusive<zeek::StringVal>(requesting_source),
                                                                     request,
                                                                     object_identifier.object_type,
                                                                     object_identifier.instance_number);
            }
            return true;
        %}

    ## ---------------------------------process_subscribe_cov_property---------------------------------
    ##  Subscribe-COV-Property Description:
    ##      The Subscribe-COV-Property service is used by a COV-client to subscribe for the receipt of
    ##      notifications of changes that may occur to the properties of a particular object
    ##  Subscribe-COV-Property Structure:
    ##      - Subscriber Process Identifier:    uint32                  -> Mandatory
    ##          + Numerical handle meaningful to the subscriber
    ##      - Monitored Object Identifier:      BACnetObjectIdentifier  -> Mandatory
    ##          + Identity of object for which a subscription is desired
    ##      - Issue Confirmed Notifications:    bool                    -> Optional
    ##          + TRUE if ConfirmedCOVNotifications, FALSE if UnconfirmedCOVNotifications
    ##      - Lifetime:                         uint32                  -> Optional
    ##          + Desired lifetime of subscription in seconds
    ##      - Monitored Property Identifier:    uint32                  -> Mandatory
    ##          + Property Identifier for which a subscription is desired
    ##      - COV Increment:                    uint32                  -> Optional
    ##          + Minimum change in the monitored property that will cause a COVNotification
    ##  Subscribe-COV-Property Event Generation:
    ##      - subscriber_process_id             -> Subscriber Process Identifier
    ##      - monitored_object_type             -> Object Type of MonitoredObject Identifier
    ##      - monitored_object_instance_number  -> Instance Number of MonitoredObject Identifier
    ##      - lifetime                          -> Lifetime
    ##      - monitored_property                -> Monitored Property Identifier
    ##      - cov_increment                     -> COV Increment
    ## ------------------------------------------------------------------------------------------------
    function process_subscribe_cov_property(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_subscribe_cov_property )
            {
                uint8 issue_confirmed = UINT8_MAX, i = 2;
                uint32 lifetime = UINT32_MAX, cov_increment = UINT32_MAX;

                uint32 subscriber_process_id = get_unsigned(${tags[0].tag_data});
                BACnetObjectIdentifier monitored_object_identifer = {${tags[1].tag_data}};

                if(${tags[i].tag_num} == 2)
                {
                    issue_confirmed = ${tags[i].tag_data[0]};
                    i += 1;
                }

                if(${tags[i].tag_num} == 3)
                {
                    lifetime = get_unsigned(${tags[0].tag_data});
                    i += 1;
                }

                i += 1;
                uint32 monitored_property = get_unsigned(${tags[i].tag_data});
                i += 2;

                if( ${tags}->size() > i)
                    cov_increment = get_unsigned(${tags[i].tag_data});

                zeek::BifEvent::enqueue_bacnet_subscribe_cov_property(connection()->zeek_analyzer(),
                                                                      connection()->zeek_analyzer()->Conn(),
                                                                      is_orig,
                                                                      invoke_id,
                                                                      subscriber_process_id,
                                                                      monitored_object_identifer.object_type,
                                                                      monitored_object_identifer.instance_number,
                                                                      lifetime,
                                                                      monitored_property,
                                                                      cov_increment);
            }
            return true;
        %}

    ## ---------------------------------process_get_event_information----------------------------------
    ##  Get-Event-Information Description:
    ##      The Get-Event-Information service is used by a client BACnet user to obtain a summary of
    ##      all active event states
    ##  Get-Event-InformationStructure:
    ##      - Last Received Object Identifier:  BACnetObjectIdentifier  -> Optional
    ##          + Last Object Identifier received in a preceding GetEventInformation-ACK
    ##  Get-Event-Information Event Generation:
    ##      - last_object_type      -> Object Type from Last Received Object Identifier
    ##      - last_instance_number  -> Instance Number from Last Received Object Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_get_event_information(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_get_event_information )
            {
                BACnetObjectIdentifier last_received;
                if( ${tags}->size() > 0)
                    last_received = {${tags[0].tag_data}};

                zeek::BifEvent::enqueue_bacnet_get_event_information(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     is_orig,
                                                                     invoke_id,
                                                                     last_received.object_type,
                                                                     last_received.instance_number);
            }
            return true;
        %}

    ###################################################################################################
    ################################ END OF CONFIRMED SERVICE REQUESTS ################################
    ###################################################################################################


    ###################################################################################################
    ########################################## COMPLEX ACKS ###########################################
    ###################################################################################################

    ## ---------------------------------process_get_alarm_summary_ack----------------------------------
    ## Get-Alarm-Summary-ACK Description:
    ##      DEPRECATED.
    ##      The Get-Alarm-Summary-ACK responds to the Get-Alarm-Summary service providing a summary of
    ##      active alarms
    ## Get-Alarm-Summary-ACK Structure:
    ##      - N/A - Deprecated
    ## Get-Alarm-Summary Event Generation:
    ##      - N/A - Deprecated
    ## ------------------------------------------------------------------------------------------------
    function process_get_alarm_summary_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_get_alarm_summary_ack )
            {
                zeek::BifEvent::enqueue_bacnet_get_alarm_summary_ack(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     is_orig,
                                                                     invoke_id);
            }
            return true;
        %}

    ## -------------------------------process_get_enrollment_summary_ack-------------------------------
    ## Get-Enrollment-Summary-ACK Description:
    ##      DEPRECATED.
    ##      The Get-Enrollment-Summary-ACK responds to the Get-Enrollment-Summary service providing a
    ##      summary of event-initiating objects
    ## Get-Enrollment-Summary-ACK Structure:
    ##      - N/A - Deprecated
    ## Get-Enrollment-Summary Event Generation:
    ##      - N/A - Deprecated
    ## ------------------------------------------------------------------------------------------------
    function process_get_enrollment_summary_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_get_enrollment_summary_ack )
            {
                zeek::BifEvent::enqueue_bacnet_get_enrollment_summary_ack(connection()->zeek_analyzer(),
                                                                          connection()->zeek_analyzer()->Conn(),
                                                                          is_orig,
                                                                          invoke_id);
            }
            return true;
        %}

    ## ----------------------------------process_atomic_read_file_ack----------------------------------
    ##  Atomic-Read-File-ACK Description:
    ##      The Atomic-Read-File-ACK service indicates the Atomic-Read service has succeeded and
    ##      responds with the data of the file
    ##  Atomic-Read-File-ACK Structure:
    ##      - End Of File:      bool                    -> Mandatory
    ##          + TRUE if this response contains last octet of file, FALSE otherwise
    ##      - Stream Access:    See below               -> Optional (Mandatory if Record Access does not exist)
    ##          + Stream-oriented file access is required. Contains parameters below:
    ##              - File Start Position:          uint32  -> Mandatory if Stream Access exists
    ##              - File Data:                    string  -> Mandatory if Stream Access exists
    ##      - Record Access:    See below               -> Optional (Mandatory if Stream Access does not exist)
    ##          + Record-oriented file access is required. Contains parameters below:
    ##              - File Start Record:            uint32  -> Mandatory if Record Access exists
    ##              - Record Count:                 uint32  -> Mandatory if Record Access exists
    ##              - Record Data:                  string  -> Mandatory if Record Access exists
    ##  Atomic-Read-File-ACK Event Generation:
    ##      - end_of_file           -> End of File
    ##      - access_type           -> Stream Access or Record Access
    ##      - file_start            -> File Start Position/File Start Record
    ##      - requested_count       -> Record Count
    ##      - data_to_return        -> File Data/Record Data
    ## ------------------------------------------------------------------------------------------------
    function process_atomic_read_file_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            uint32 record_count = UINT32_MAX;
            string access_type;
            string data_to_return;

            uint8 end_of_file = ${tags[0].tag_length_a};
            uint32 file_start = get_unsigned(${tags[2].tag_data});

            if(${tags[1].tag_num} == 0)
            {
                access_type = "Stream";
                data_to_return = get_string2(${tags[3].tag_data});

                zeek::file_mgr->DataIn(${tags[3].tag_data}.begin(),
                                        ${tags[3].tag_length},
                                        file_start,
                                        connection()->zeek_analyzer()->GetAnalyzerTag(),
                                        connection()->zeek_analyzer()->Conn(),
                                        is_orig);

                if( end_of_file == 1 )
                {
                    zeek::file_mgr->EndOfFile(connection()->zeek_analyzer()->GetAnalyzerTag(),
                                              connection()->zeek_analyzer()->Conn(),
                                              is_orig);
                }
            }
            else
            {
                access_type = "Record";
                record_count = get_unsigned(${tags[3].tag_data});
                data_to_return = get_string2(${tags[4].tag_data});
            }

            if ( ::bacnet_atomic_read_file_ack )
            {
                zeek::BifEvent::enqueue_bacnet_atomic_read_file_ack(connection()->zeek_analyzer(),
                                                                    connection()->zeek_analyzer()->Conn(),
                                                                    is_orig,
                                                                    invoke_id,
                                                                    end_of_file,
                                                                    zeek::make_intrusive<zeek::StringVal>(access_type),
                                                                    file_start,
                                                                    record_count,
                                                                    zeek::make_intrusive<zeek::StringVal>(data_to_return));
            }
            return true;
        %}

    ## ---------------------------------process_atomic_write_file_ack----------------------------------
    ##  Atomic-Write-File-ACK Description:
    ##      The Atomic-Write-File-ACK service indicates the Atomic-Write-File service has succeeded
    ##      and responds with the offset where the data was written.
    ##  Atomic-Write-File-ACK Structure:
    ##      - File Start    -> uint32   -> Mandatory
    ##          + Number of octets (if stream) or records (if record) from the beginning of the file
    ##            for the data to be written
    ##  Atomic-Write-File-ACK Event Generation:
    ##      - access_type   -> Stream | Record
    ##      - file_start    -> File Start
    ## ------------------------------------------------------------------------------------------------
    function process_atomic_write_file_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_atomic_write_file_ack )
            {
                string access_type = "";
                if(${tags[0].tag_num} == 0)
                    access_type = "Stream";
                else
                    access_type = "Record";

                uint32 file_start = get_unsigned(${tags[0].tag_data});

                zeek::BifEvent::enqueue_bacnet_atomic_write_file_ack(connection()->zeek_analyzer(),
                                                                     connection()->zeek_analyzer()->Conn(),
                                                                     is_orig,
                                                                     invoke_id,
                                                                     zeek::make_intrusive<zeek::StringVal>(access_type),
                                                                     file_start);
            }
            return true;
        %}

    ## -----------------------------------process_create_object_ack------------------------------------
    ##  Create-Object-ACK Description:
    ##      The Create-Object-ACK indicates the Create-Object service has succeeded and responds with
    ##      the newly created object's Object Identifier
    ##  Create-Object-ACK Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + Object Identifier of the newly created object
    ##  Create-Object Event Generation:
    ##      - object_type        -> Object Type from Object Identifier
    ##      - instance_number    -> Instance Number from Object Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_create_object_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_create_object_ack )
            {
                BACnetObjectIdentifier result_object_identifier = {${tags[0].tag_data}};
                zeek::BifEvent::enqueue_bacnet_create_object_ack(connection()->zeek_analyzer(),
                                                                 connection()->zeek_analyzer()->Conn(),
                                                                 is_orig,
                                                                 invoke_id,
                                                                 result_object_identifier.object_type,
                                                                 result_object_identifier.instance_number);
            }
            return true;
        %}

    ## -----------------------------------process_read_property_ack------------------------------------
    ##  Read-Property-ACK Description:
    ##      The Read-Property-ACK service indicates the service has succeeded and responds with the
    ##      requested data
    ##  Read-Property-ACK Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + Object whose property is being read/returned
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be read and returned
    ##      - Property Array Index: uint32                  -> Optional
    ##          + Array index of the element of the returned property
    ##      - Property Value:       Variable                -> Mandatory
    ##          + Value of property being returned
    ##  Read-Property-ACK Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ##      - property_value                ->  Value of Property
    ## ------------------------------------------------------------------------------------------------
    function process_read_property_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_read_property_ack )
            {
                if ( ${tags}->size() > 2 )
                {
                    BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                    uint32 property_identifier = get_unsigned(${tags[1].tag_data});

                    uint32 property_array_index = UINT32_MAX;
                    if((${tags[2].tag_class} == 1) && (${tags[2].tag_num} == 2)) // Context tag (tag_class == 1)
                    {
                        property_array_index = get_unsigned(${tags[2].tag_data});
                    }

                    uint32 i = 3;
                    while (i < ${tags}->size()) {
                        if((${tags[i].named_tag} != OPENING) &&
                            ${tags[i].named_tag} != CLOSING) 
                        {
                            string property_value = "";
                            property_value = parse_tag(${tags[i].tag_num},${tags[i].tag_class},${tags[i].tag_data},${tags[i].tag_length},${tags[i].tag_length_a});

                            zeek::BifEvent::enqueue_bacnet_read_property_ack(connection()->zeek_analyzer(),
                                                                            connection()->zeek_analyzer()->Conn(),
                                                                            is_orig,
                                                                            invoke_id,
                                                                            zeek::make_intrusive<zeek::StringVal>("read-property-ack"),
                                                                            object_identifier.object_type,
                                                                            object_identifier.instance_number,
                                                                            property_identifier,
                                                                            property_array_index,
                                                                            zeek::make_intrusive<zeek::StringVal>(property_value));
                        }
                        i += 1;
                    }
                }
            }
            return true;
        %}

    ## -------------------------------process_read_property_multiple_ack-------------------------------
    ##  Read-Property-Multiple-ACK Description:
    ##      The Read-Property-Multiple-ACK service indicates the service has succeeded and responds
    ##      with the requested data
    ##  Read-Property-Multiple-ACK Structure:
    ##      - List of Read Access Results
    ## ------------------------------------------------------------------------------------------------
    function process_read_property_multiple_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_read_property_ack )
            {
                uint32 property_array_index = UINT32_MAX;
                uint32 property_identifier;
                BACnetObjectIdentifier object_identifier;
                uint8 tag_status = 4;
                uint8 property_exists = 0;
                string property_value;
                for ( uint32 x = 0; x < ${tags}->size(); ++x ){
                    object_identifier = {${tags[x].tag_data}};
                    x += 1;
                    property_identifier = UINT32_MAX;
                    property_array_index = UINT32_MAX;
                    for ( uint32 i = x; i < ${tags}->size(); ++i ){
                        if((${tags[i].named_tag} == OPENING)){
                            // Opening Tag
                            tag_status = ${tags[i].tag_num};
                            property_exists = 0;
                            continue;
                        }else if(${tags[i].named_tag} == CLOSING){
                            // Closing Tag
                            if(${tags[i].tag_num} == 1){
                                x = i;
                                break;
                            }else if(property_exists == 0){
                                // If we get to this close tag and a property hasn't been written yet, write to log with null
                                zeek::BifEvent::enqueue_bacnet_read_property_ack(connection()->zeek_analyzer(),
                                                                                 connection()->zeek_analyzer()->Conn(),
                                                                                 is_orig,
                                                                                 invoke_id,
                                                                                 zeek::make_intrusive<zeek::StringVal>("read-property-multiple-ack"),
                                                                                 object_identifier.object_type,
                                                                                 object_identifier.instance_number,
                                                                                 property_identifier,
                                                                                 property_array_index,
                                                                                 zeek::make_intrusive<zeek::StringVal>(""));
                            }
                        }else if(${tags[i].tag_class} == 1){
                            property_identifier = get_unsigned(${tags[i].tag_data});
                            // If property identifier is 76 (object-list), the following values will be object identifiers (identifier 75)
                            if ( property_identifier == 76)
                                property_identifier = 75;
                        }else if(tag_status == 5){
                            i += 2;
                            property_exists = 1;
                            property_value = "PropertyError";
                            zeek::BifEvent::enqueue_bacnet_read_property_ack(connection()->zeek_analyzer(),
                                                                             connection()->zeek_analyzer()->Conn(),
                                                                             is_orig,
                                                                             invoke_id,
                                                                             zeek::make_intrusive<zeek::StringVal>("read-property-multiple-ack"),
                                                                             object_identifier.object_type,
                                                                             object_identifier.instance_number,
                                                                             property_identifier,
                                                                             property_array_index,
                                                                             zeek::make_intrusive<zeek::StringVal>(property_value));
                        }else{
                            property_value = parse_tag(${tags[i].tag_num},${tags[i].tag_class},${tags[i].tag_data},${tags[i].tag_length},${tags[i].tag_length_a});
                            property_exists = 1;
                            zeek::BifEvent::enqueue_bacnet_read_property_ack(connection()->zeek_analyzer(),
                                                                             connection()->zeek_analyzer()->Conn(),
                                                                             is_orig,
                                                                             invoke_id,
                                                                             zeek::make_intrusive<zeek::StringVal>("read-property-multiple-ack"),
                                                                             object_identifier.object_type,
                                                                             object_identifier.instance_number,
                                                                             property_identifier,
                                                                             property_array_index,
                                                                             zeek::make_intrusive<zeek::StringVal>(property_value));
                        }
                    }
                }
            }
            return true;
        %}

    ## -----------------------------process_confirmed_private_transfer_ack-----------------------------
    ##  Confirmed-Private-Transfer-ACK Description:
    ##      The Confirmed-Private-Transfer-ACK indicates the Confirmed-Private-Transfer service has
    ##      succeeded and responds with vendor id and service number
    ##  Confirmed-Private-Transfer-ACK Structure:
    ##      - Vendor ID:        uint32      -> Mandatory
    ##          + Vendor identification code for which this is a result for
    ##      - Service Number:   uint32      -> Mandatory
    ##          + Proprietary service for which this is a result for
    ##      - Result Block:     Variable    -> Optional
    ##          + Any additional results from the execution of the service
    ##  Confirmed-Private-Transfer Event Generation:
    ##      - vendor_id         -> Vendor ID
    ##      - service_number    -> Service Number
    ## ------------------------------------------------------------------------------------------------
    function process_confirmed_private_transfer_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_confirmed_private_transfer_ack )
            {
                uint32 vendor_id = get_unsigned(${tags[0].tag_data});
                uint32 service_number = get_unsigned(${tags[1].tag_data});

                zeek::BifEvent::enqueue_bacnet_confirmed_private_transfer_ack(connection()->zeek_analyzer(),
                                                                              connection()->zeek_analyzer()->Conn(),
                                                                              is_orig,
                                                                              invoke_id,
                                                                              vendor_id,
                                                                              service_number);
            }
            return true;
        %}

    ## --------------------------------------process_vt_open_ack---------------------------------------
    ##  VT-Open-ACK Description:
    ##      The VT-Open-ACK indicates the VT-Open service has succeeded and responds with the remote
    ##      VT session identifier
    ##  VT-Open-ACK Structure:
    ##      - Remote VT Session Identifier: uint8   -> Mandatory
    ##          + Unique VT-session identifier
    ##  VT-Open Event Generation:
    ##      - remote_session_identifier -> Remote VT Session Identifier
    ## ------------------------------------------------------------------------------------------------
    function process_vt_open_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_vt_open_ack )
            {
                uint8 remote_session_identifier = ${tags[0].tag_data[0]};
                zeek::BifEvent::enqueue_bacnet_vt_open_ack(connection()->zeek_analyzer(),
                                                           connection()->zeek_analyzer()->Conn(),
                                                           is_orig,
                                                           invoke_id,
                                                           remote_session_identifier);
            }
            return true;
        %}

    ## --------------------------------------process_vt_data_ack---------------------------------------
    ##  VT-Data-ACK Description:
    ##      The VT-Data-ACK indicates the VT-Data service has succeeded and responds with the "All New
    ##      Data Accepted" and "Accepted Octet Count" parameters
    ##  VT-Data-ACK Structure:
    ##      - All New Data Accepted:    bool    -> Mandatory
    ##          + True if VT-new Data were accepted by user, False otherwise
    ##      - Accepted Octet Count:     uint32  -> Only if All New Data Accepted is False
    ##          + Number of octets that were accepted from the VT-new Data
    ##  VT-Data Event Generation:
    ##      - data_accepted     -> All New Data Accepted
    ##      - accepted_count    -> Accepted Octet Count
    ## ------------------------------------------------------------------------------------------------
    function process_vt_data_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_vt_data_ack )
            {
                uint8 data_accepted = ${tags[0].tag_data[0]};
                uint32 accepted_count = UINT32_MAX;
                if(data_accepted == 0){
                    accepted_count = get_unsigned(${tags[1].tag_data});
                }
                zeek::BifEvent::enqueue_bacnet_vt_data_ack(connection()->zeek_analyzer(),
                                                           connection()->zeek_analyzer()->Conn(),
                                                           is_orig,
                                                           invoke_id,
                                                           data_accepted,
                                                           accepted_count);
            }
            return true;
        %}

    ## -------------------------------------process_read_range_ack-------------------------------------
    ##  Read-Range-ACK Description:
    ##      The Read-Range-ACK service indicates the service has succeeded and responds with the
    ##      requested data
    ##  Read-Range-ACK Structure:
    ##      - Object Identifier:    BACnetObjectIdentifier  -> Mandatory
    ##          + Object that was read
    ##      - Property Identifier:  uint32                  -> Mandatory
    ##          + BACnetPropertyIdentifier of property to be read and returned
    ##      - Property Array Index: uint32                  -> Optional
    ##          + Array index of the element of the property to be returned
    ##      - Result Flags:         enum                    -> Mandatory
    ##          + Conveys several flags that describe characteristics of the response data
    ##      - Item Count:           uint32                  -> Mandatory
    ##          + Number of items returned
    ##      - Item Data:            list                    -> Mandatory
    ##          + List of requested data
    ##  Read-Range Event Generation:
    ##      - object_type                   ->  Object Type from Object Identifier
    ##      - object_instance_number        ->  Instance Number from Object Identifier
    ##      - property_identifier           ->  Property Identifier
    ##      - property_array_index          ->  Property Array Index
    ##      - result_flags                  ->  Result Flags
    ##      - item_count                    ->  Item Count
    ##  TODO: Add logic to send read-range items to bacnet_property.log file. Items utilize context-
    ##        specific flags
    ## ------------------------------------------------------------------------------------------------
    function process_read_range_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_read_range_ack )
            {
                if ( ${tags}->size() > 2 )
                {
                    BACnetObjectIdentifier object_identifier = {${tags[0].tag_data}};
                    uint32 property_identifier = get_unsigned(${tags[1].tag_data});
                    uint32 property_array_index = UINT32_MAX;
                    uint8 result_flags = UINT8_MAX;
                    uint32 item_count = UINT32_MAX;

                    uint8 i = 2;
                    uint8 x;
                    if( ${tags[2].tag_num} == 2 )
                    {
                        property_array_index = get_unsigned(${tags[2].tag_data});
                        i += 1;
                    }
                    x = i + 1;
                    if ( ${tags}->size() > x )
                    {
                        result_flags = ${tags[i].tag_data[0]};
                        item_count = get_unsigned(${tags[i+1].tag_data});
                    }

                    zeek::BifEvent::enqueue_bacnet_read_range_ack(connection()->zeek_analyzer(),
                                                                  connection()->zeek_analyzer()->Conn(),
                                                                  is_orig,
                                                                  invoke_id,
                                                                  object_identifier.object_type,
                                                                  object_identifier.instance_number,
                                                                  property_identifier,
                                                                  property_array_index,
                                                                  result_flags,
                                                                  item_count);
                }
            }
            return true;
        %}

    ## -------------------------------process_get_event_information_ack--------------------------------
    ##  Get-Event-Information-ACK Description:
    ##      The Get-Event-Information-ACK indicates the service has succeeded and responds with a list
    ##      of events
    ## ------------------------------------------------------------------------------------------------
    function process_get_event_information_ack(is_orig: bool, invoke_id: uint8, tags: BACnet_Tag[]): bool
        %{
            if ( ::bacnet_get_event_information_ack )
            {
                zeek::BifEvent::enqueue_bacnet_get_event_information_ack(connection()->zeek_analyzer(),
                                                                         connection()->zeek_analyzer()->Conn(),
                                                                         is_orig,
                                                                         invoke_id);
            }
            return true;
        %}


    ###################################################################################################
    ####################################### END OF COMPLEX ACKS #######################################
    ###################################################################################################
};
