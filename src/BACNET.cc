// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "BACNET.h"

#include <zeek/Reporter.h>

#include "events.bif.h"

using namespace analyzer::BACNET;

BACNET_Analyzer::BACNET_Analyzer(zeek::Connection* c): zeek::analyzer::Analyzer("BACNET", c)
{
    interp = new binpac::BACNET::BACNET_Conn(this);
}

BACNET_Analyzer::~BACNET_Analyzer()
{
    delete interp;
}

void BACNET_Analyzer::Done()
{
    Analyzer::Done();
}

void BACNET_Analyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const zeek::IP_Hdr* ip, int caplen)
{
    Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

    try
    {
        interp->NewData(orig, data, data + len);
    }
    catch ( const binpac::Exception& e )
    {
    }
}
