// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

#include "Plugin.h"
#include "analyzer/Component.h"

namespace plugin 
{ 
    namespace ICSNPP_BACNET 
    {
        Plugin plugin;
    }
}

using namespace plugin::ICSNPP_BACNET;

zeek::plugin::Configuration Plugin::Configure() 
{
    AddComponent(new ::analyzer::Component("BACNET",::analyzer::BACNET::BACNET_Analyzer::InstantiateAnalyzer));    

    zeek::plugin::Configuration config;
    config.name = "ICSNPP::BACnet";
    config.description = "BACnet Protocol analyzer";
    config.version.major = 1;
    config.version.minor = 1;
    
    return config;
}
