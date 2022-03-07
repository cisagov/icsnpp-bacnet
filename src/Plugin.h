// Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.
#pragma once

#include <zeek/plugin/Plugin.h>
#include "BACNET.h"

namespace plugin
{
    namespace ICSNPP_BACNET
    {
        class Plugin : public zeek::plugin::Plugin
        {
            protected:
                virtual zeek::plugin::Configuration Configure();
        };

        extern Plugin plugin;
    }
}