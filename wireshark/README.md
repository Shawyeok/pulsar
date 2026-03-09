<!--

    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.

-->

# Pulsar Wireshark Dissector

A Lua plugin for Wireshark that dissects the Apache Pulsar binary protocol.

## Requirements

- Wireshark 3.x or 4.x (tested on 4.x)
- The Protobuf dissector must be enabled in Wireshark (it is by default)

## Step 1: Register PulsarApi.proto

The plugin delegates Protobuf decoding to Wireshark's built-in Protobuf dissector,
so Wireshark needs to know where `PulsarApi.proto` is.

1. Copy `pulsar-common/src/main/proto/PulsarApi.proto` to a directory of your choice.

2. Open Wireshark → **Edit > Preferences > Protocols > Protobuf > Protobuf search paths**.

3. Add the directory containing `PulsarApi.proto`.

4. Check **Dissect Protobuf fields as Wireshark fields**.
   This enables the `pbf.pulsar.proto.*` display filter namespace.

## Step 2: Install pulsar.lua

1. Open Wireshark → **Help > About Wireshark > Folders** and note the
   **Personal Lua Plugins** path (e.g. `~/.local/lib/wireshark/plugins/`).

2. Copy `pulsar.lua` to that directory.

3. Reload Lua plugins: **Analyze > Reload Lua Plugins** (or restart Wireshark).

## Step 3: Capture and filter

The dissector registers on TCP port **6650** by default. To change the port,
go to **Edit > Preferences > Protocols > Pulsar**.

Useful display filter to show all Pulsar traffic except keep-alive ping/pong:

```
tcp.port eq 6650 and pulsar and pbf.pulsar.proto.BaseCommand.type ne "ping" and pbf.pulsar.proto.BaseCommand.type ne "pong"
```

Filter by a specific command type:

```
pbf.pulsar.proto.BaseCommand.type eq "send"
pbf.pulsar.proto.BaseCommand.type eq "message"
pbf.pulsar.proto.BaseCommand.type eq "connect"
```

## What the dissector shows

Each Pulsar frame is broken down into:

| Field | Description |
|---|---|
| `pulsar.total_size` | Frame length (excludes the 4-byte length prefix itself) |
| `pulsar.cmd_size` | Size of the serialized `BaseCommand` protobuf |
| `pulsar.cmd` | `BaseCommand` protobuf (decoded by the Protobuf dissector) |
| `pulsar.magic` | Magic bytes: `0x0e01` = CRC32C checksum follows, `0x0e02` = broker entry metadata follows |
| `pulsar.checksum` | CRC32C checksum over metadata + payload |
| `pulsar.broker_meta_size` | Size of the `BrokerEntryMetadata` protobuf (protocol v16+) |
| `pulsar.broker_meta` | `BrokerEntryMetadata` protobuf |
| `pulsar.metadata_size` | Size of the `MessageMetadata` protobuf |
| `pulsar.metadata` | `MessageMetadata` protobuf |
| `pulsar.payload` | Raw message payload bytes |

The **Info** column in the packet list shows the command type name
(e.g. `SEND`, `MESSAGE`, `CONNECT`, `ACK`, …).
