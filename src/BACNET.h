// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_BACNET_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_BACNET_H

#include "events.bif.h"

#include <zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h>

#include "bacnet_pac.h"

namespace analyzer
{
    namespace BACNET
    {
        class BACNET_Analyzer : public zeek::analyzer::Analyzer
        {
            public:
                BACNET_Analyzer(zeek::Connection* conn);
                virtual ~BACNET_Analyzer();

                virtual void Done();

                virtual void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen);

                static  zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
                {
                    return new BACNET_Analyzer(conn);
                }

            protected:
                binpac::BACNET::BACNET_Conn* interp;

        };

    }
}

#endif