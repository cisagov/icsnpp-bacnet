##! main.zeek
##!
##! Binpac BACnet Protocol Analyzer - Contains the file analysis script-layer functionality 
##!                                   for extracting Atomic files.
##!
##! Author:   Stephen Kleinheider
##! Contact:  stephen.kleinheider@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

@load base/frameworks/files
@load ./main

module Bacnet;

export {
    ## Default file handle provider for BACNET
    global get_file_handle: function(c: connection, is_orig: bool): string;

    ## Default file describer for BACNET
    global describe_file: function(f: fa_file): string;
}

function get_file_handle(c: connection, is_orig: bool): string
    {
        return cat(Analyzer::ANALYZER_BACNET, c$start_time, c$id, is_orig);
    }

function describe_file(f: fa_file): string
    {
        return "bacnet_atomic";
    }

event zeek_init() &priority=5
    {
        Files::register_protocol(Analyzer::ANALYZER_BACNET,
                                 [$get_file_handle = Bacnet::get_file_handle,
                                  $describe        = Bacnet::describe_file]);
    }
