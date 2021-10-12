%include zeek/binpac.pac
%include zeek/zeek.pac

%extern{
    #include "events.bif.h"
%}

analyzer BACNET withcontext {
    connection: BACNET_Conn;
    flow:       BACNET_Flow;
};

connection BACNET_Conn(zeek_analyzer: ZeekAnalyzer) {
    upflow   = BACNET_Flow(true);
    downflow = BACNET_Flow(false);
};

%include bacnet-protocol.pac

flow BACNET_Flow(is_orig: bool) {
    datagram = BACNET_PDU(is_orig) withcontext(connection, this);

};

%include bacnet-analyzer.pac