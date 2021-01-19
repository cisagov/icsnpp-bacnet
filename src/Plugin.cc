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

plugin::Configuration Plugin::Configure() 
{
    AddComponent(new ::analyzer::Component("BACNET",::analyzer::BACNET::BACNET_Analyzer::InstantiateAnalyzer));    

    plugin::Configuration config;
    config.name = "ICSNPP::BACnet";
    config.description = "BACnet Protocol analyzer";
    config.version.major = 1;
    config.version.minor = 0;
    
    return config;
}
