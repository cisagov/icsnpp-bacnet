# ICSNPP-BACnet

Industrial Control Systems Network Protocol Parsers (ICSNPP) - BACnet.

## Overview

ICSNPP-BACnet is a Zeek plugin for parsing and logging fields within the BACnet protocol.

This plugin was developed to be fully customizable, so if you would like to drill down into specific BACnet packets and log certain variables, add the logging functionality to [scripts/icsnpp/bacnet/main.zeek](scripts/icsnpp/bacnet/main.zeek). The functions within [scripts/icsnpp/bacnet/main.zeek](scripts/icsnpp/bacnet/main.zeek) and [src/events.bif](src/events.bif) should prove to be a good guide on how to add new logging functionality.

This parser produces four log files. These log files are defined in [scripts/icsnpp/bacnet/main.zeek](scripts/icsnpp/bacnet/main.zeek).
* bacnet.log
* bacnet_discovery.log
* bacnet_property.log
* bacnet_device_control.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-bacnet
```

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly you will see `ICSNPP::BACnet`.

If you have ZKG configured to load packages (see @load packages in quickstart guide), this plugin and scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/bacnet` to your command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-bacnet.git
zeek -Cr icsnpp-bacnet/tests/traces/bacnet_example.pcap icsnpp/bacnet
```

### Manual Install

To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-bacnet.git
cd icsnpp-bacnet/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::BACnet
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::BACnet
```

To run this plugin in a site deployment you will need to add the line `@load icsnpp/bacnet` to your `site/local.zeek` file in order to load this plugin's scripts.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/bacnet` to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-bacnet/tests/traces/bacnet_example.pcap icsnpp/bacnet
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the ICSNPP_Bacnet.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/ICSNPP_Bacnet.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### BACnet Header Log (bacnet.log)

#### Overview

This log captures BACnet header information for every BACnet/IP packet and logs it to **bacnet.log**. BACnet has two different protocol data layer messages (PDUs) - Application Protocol Data Unit (APDU) and Network Protocol Data Unit (NPDU). Both APDU and NPDU messages are logged to bacnet.log, but fields captured and logged are slightly different as seen below.

#### Fields Captured (BACnet-APDU Packets)

| Field         | Type      | Description                                                   |
| ------------- |-----------|---------------------------------------------------------------|
| ts            | time      | Timestamp                                                     |
| uid           | string    | Unique ID for this connection                                 |
| id            | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig       | bool      | True if the packet is sent from the originator                |
| source_h      | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p      | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p | port      | Destination Port (see *Source and Destination Fields*)        |
| bvlc_function | string    | BVLC function                                                 |
| pdu_type      | string    | APDU service type                                             |
| pdu_service   | string    | APDU service choice                                           |
| invoke_id     | count     | Unique ID for all outstanding confirmed request/ACK APDUs     |
| result_code   | string    | Error code or reject/abort reason                             |

#### Fields Captured (BACnet-NPDU Packets)

| Field         | Type      | Description                                                   |
| ------------- |-----------|---------------------------------------------------------------|
| ts            | time      | Timestamp                                                     |
| uid           | string    | Unique ID for this connection                                 |
| id            | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig       | bool      | True if the packet is sent from the originator                |
| source_h      | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p      | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p | port      | Destination Port (see *Source and Destination Fields*)        |
| bvlc_function | string    | BVLC function                                                 |
| pdu_type      | string    | static "NPDU" string                                          |
| pdu_service   | string    | NPDU message type                                             |
| invoke_id     | count     | NPDU destination network address                              |
| result_code   | string    | N/A                                                           |

### Discovery Log (bacnet_discovery.log)

#### Overview

This log captures important fields for Who-Is, I-Am, Who-Has, and I-Have messages and logs them to **bacnet_discovery.log**.

#### Fields Captured

| Field             | Type      | Description                                                     |
| ----------------- |-----------|-----------------------------------------------------------------|
| ts                | time      | Timestamp                                                       |
| uid               | string    | Unique ID for this connection                                   |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)              |
| is_orig           | bool      | True if the message is sent from the originator                 |
| source_h          | address   | Source IP address (see *Source and Destination Fields*)         |
| source_p          | port      | Source Port (see *Source and Destination Fields*)               |
| destination_h     | address   | Destination IP address (see *Source and Destination Fields*)    |
| destination_p     | port      | Destination Port (see *Source and Destination Fields*)          |
| pdu_service       | string    | APDU service choice (who-is, i-am, who-has, or i-have)          |
| object_type       | string    | BACnet device's object type                                     |
| instance_number   | count     | BACnet device's instance number                                 |
| vendor            | string    | BACnet device's vendor name                                     |
| range             | string    | Range of instance numbers                                       |
| object_name       | string    | Object name searching for (who-has) or responding with (i-have) |

### Property Log (bacnet_property.log)

#### Overview

This log captures important variables for Read-Property-Request, Read-Property-ACK, and Write-Property-Request messages and logs them to **bacnet_property.log**.

#### Fields Captured

| Field             | Type      | Description                                                   |
| ----------------- |-----------|---------------------------------------------------------------|
| ts                | time      | Timestamp                                                     |
| uid               | string    | Unique ID for this connection                                 |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)            |
| is_orig           | bool      | True if the message is sent from the originator               |
| source_h          | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p          | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h     | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p     | port      | Destination Port (see *Source and Destination Fields*)        |
| invoke_id         | count     | Unique ID for all outstanding confirmed request/ACK APDUs     |
| pdu_service       | string    | APDU service choice (read or write property services)         |
| object_type       | string    | BACnet device's object type                                   |
| instance_number   | count     | BACnet device's instance number                               |
| property          | string    | Property type                                                 |
| array_index       | count     | Property array index                                          |
| value             | string    | Value of property                                             |

### Device Control Log (bacnet_device_control.log)

#### Overview

This log captures important variables for Reinitialize-Device and Device-Communication-Control messages and logs them to **bacnet_device_control.log**.

#### Fields Captured

| Field             | Type      | Description                                                                |
| ----------------- |-----------|--------------------------------------------------------------------------- |
| ts                | time      | Timestamp                                                                  |
| uid               | string    | Unique ID for this connection                                              |
| id                | conn_id   | Default Zeek connection info (IP addresses, ports)                         |
| is_orig           | bool      | True if the message is sent from the originator                            |
| source_h          | address   | Source IP address (see *Source and Destination Fields*)                    |
| source_p          | port      | Source Port (see *Source and Destination Fields*)                          |
| destination_h     | address   | Destination IP address (see *Source and Destination Fields*)               |
| destination_p     | port      | Destination Port (see *Source and Destination Fields*)                     |
| invoke_id         | count     | Unique ID for all outstanding confirmed request/ACK APDUs                  |
| pdu_service       | string    | APDU service choice (reinitialize_device or device_communication_control)  |
| time_duration     | count     | Number of minutes device should ignore other APDUs                         |
| device_state      | string    | State to put device into                                                   |
| password          | string    | Password                                                                   |
| result            | string    | Success, Error, Reject, or Abort                                           |
| result_code       | string    | Resulting Error/Reject/Abort Code                                          |

### Source and Destination Fields

#### Overview

Zeek's typical behavior is to focus on and log packets from the originator and not log packets from the responder. However, most ICS protocols contain useful information in the responses, so the ICSNPP parsers log both originator and responses packets. Zeek's default behavior, defined in its `id` struct, is to never switch these originator/responder roles which leads to inconsistencies and inaccuracies when looking at ICS traffic that logs responses.

The default Zeek `id` struct contains the following logged fields:
* id.orig_h (Original Originator/Source Host)
* id.orig_p (Original Originator/Source Port)
* id.resp_h (Original Responder/Destination Host)
* id.resp_p (Original Responder/Destination Port)

Additionally, the `is_orig` field is a boolean field that is set to T (True) when the id_orig fields are the true originators/source and F (False) when the id_resp fields are the true originators/source.

To not break existing platforms that utilize the default `id` struct and `is_orig` field functionality, the ICSNPP team has added four new fields to each log file instead of changing Zeek's default behavior. These four new fields provide the accurate information regarding source and destination IP addresses and ports:
* source_h (True Originator/Source Host)
* source_p (True Originator/Source Port)
* destination_h (True Responder/Destination Host)
* destination_p (True Responder/Destination Port)

The pseudocode below shows the relationship between the `id` struct, `is_orig` field, and the new `source` and `destination` fields.

```
if is_orig == True
    source_h == id.orig_h
    source_p == id.orig_p
    destination_h == id.resp_h
    destination_p == id.resp_p
if is_orig == False
    source_h == id.resp_h
    source_p == id.resp_p
    destination_h == id.orig_h
    destination_p == id.orig_p
```

#### Example

The table below shows an example of these fields in the log files. The first log in the table represents a Modbus request from 192.168.1.10 -> 192.168.1.200 and the second log represents a Modbus reply from 192.168.1.200 -> 192.168.1.10. As shown in the table below, the `id` structure lists both packets as having the same originator and responder, but the `source` and `destination` fields reflect the true source and destination of these packets.

| id.orig_h    | id.orig_p | id.resp_h     | id.resp_p | is_orig | source_h      | source_p | destination_h | destination_p |
| ------------ | --------- |---------------|-----------|---------|---------------|----------|---------------|-------------- |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | T       | 192.168.1.10  | 47785    | 192.168.1.200 | 502           |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | F       | 192.168.1.200 | 502      | 192.168.1.10  | 47785         |

## BACnet File Extraction

BACnet contains two messages for sending and receiving files: Atomic-Read-File and Atomic-Write-File. This plugin will extract files sent via these two messages and pass the extracted files to Zeek's file analysis framework.

## Troubleshooting

By default, this BACnet parser uses a Zeek DPD signature to detect BACnet traffic. If you are seeing false positives in your BACnet logs and your BACnet traffic is operating on UDP port 47808 you can disable this DPD signature by removing or commenting-out the first line of [scripts/icsnpp/bacnet/\_\_load\_\_.zeek](scripts/icsnpp/bacnet/__load__.zeek).

Default configuration, parses BACnet traffic on all UDP ports, but may produce false positives
```bash
@load-sigs ./dpd.sig
@load ./main
@load ./files
```

Modified configuration, only parses BACnet traffic on UDP/47808
```bash
# @load-sigs ./dpd.sig
@load ./main
@load ./files
```

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2023 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.
