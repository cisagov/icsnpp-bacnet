cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(Plugin)

include(ZeekPlugin)

# Disable C/C++ runtime assert() calls to avoid BinPAC-generated aborts that
# stem from optional fields being absent in segmented messages.
add_compile_definitions(NDEBUG)

zeek_plugin_begin(ICSNPP Bacnet)
    zeek_plugin_cc(src/BACNET.cc src/Plugin.cc)
    zeek_plugin_bif(src/events.bif)
    zeek_plugin_pac(src/bacnet.pac src/bacnet-analyzer.pac src/bacnet-protocol.pac)
    zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()