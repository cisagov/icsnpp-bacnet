// Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_BACNET_BACNET_H
#define ANALYZER_PROTOCOL_BACNET_BACNET_H

#include "events.bif.h"

#if ZEEK_VERSION_NUMBER >= 40100
#include <zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h>
#else
#include <zeek/analyzer/protocol/udp/UDP.h>
#endif

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