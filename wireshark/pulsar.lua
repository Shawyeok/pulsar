--[[

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

]]

-- Pulsar binary protocol wire format:
--
-- Simple command (no payload):
--   [TOTAL_SIZE(4)] [CMD_SIZE(4)] [CMD]
--
-- Payload command (with broker entry metadata, protocol v16+):
--   [TOTAL_SIZE(4)] [CMD_SIZE(4)] [CMD]
--   [BROKER_MAGIC(2)=0x0e02] [BROKER_META_SIZE(4)] [BROKER_META]
--   [MAGIC(2)=0x0e01] [CHECKSUM(4)] [METADATA_SIZE(4)] [METADATA] [PAYLOAD]
--
-- Payload command (without broker entry metadata):
--   [TOTAL_SIZE(4)] [CMD_SIZE(4)] [CMD]
--   [MAGIC(2)=0x0e01] [CHECKSUM(4)] [METADATA_SIZE(4)] [METADATA] [PAYLOAD]
--
-- Payload command (no checksum, older protocol):
--   [TOTAL_SIZE(4)] [CMD_SIZE(4)] [CMD]
--   [METADATA_SIZE(4)] [METADATA] [PAYLOAD]

local MAGIC_CRC32C       = 0x0e01
local MAGIC_BROKER_ENTRY = 0x0e02

local protobuf_dissector = Dissector.get("protobuf")

local pulsar_protocol = Proto("Pulsar", "Apache Pulsar")

-- ProtoFields for the Pulsar wire-format framing fields
local f_total_size       = ProtoField.uint32("pulsar.total_size",        "Total Frame Size",               base.DEC)
local f_cmd_size         = ProtoField.uint32("pulsar.cmd_size",          "Command Size",                   base.DEC)
local f_cmd              = ProtoField.bytes ("pulsar.cmd",               "Command (Protobuf)",             base.SPACE)
local f_magic            = ProtoField.uint16("pulsar.magic",             "Magic",                          base.HEX)
local f_checksum         = ProtoField.uint32("pulsar.checksum",          "Checksum (CRC32C)",              base.HEX)
local f_broker_meta_size = ProtoField.uint32("pulsar.broker_meta_size",  "Broker Entry Metadata Size",     base.DEC)
local f_broker_meta      = ProtoField.bytes ("pulsar.broker_meta",       "Broker Entry Metadata (Protobuf)", base.SPACE)
local f_metadata_size    = ProtoField.uint32("pulsar.metadata_size",     "Message Metadata Size",          base.DEC)
local f_metadata         = ProtoField.bytes ("pulsar.metadata",          "Message Metadata (Protobuf)",    base.SPACE)
local f_payload          = ProtoField.bytes ("pulsar.payload",           "Payload",                        base.SPACE)

pulsar_protocol.fields = {
    f_total_size, f_cmd_size, f_cmd,
    f_magic, f_checksum,
    f_broker_meta_size, f_broker_meta,
    f_metadata_size, f_metadata,
    f_payload,
}

-- Expert info fields
local ef_too_short = ProtoExpert.new(
    "pulsar.too_short", "Pulsar frame truncated",
    expert.group.MALFORMED, expert.severity.ERROR)
pulsar_protocol.experts = { ef_too_short }

-- Command type names from BaseCommand.Type enum (PulsarApi.proto)
local COMMAND_TYPES = {
    [2]  = "CONNECT",
    [3]  = "CONNECTED",
    [4]  = "SUBSCRIBE",
    [5]  = "PRODUCER",
    [6]  = "SEND",
    [7]  = "SEND_RECEIPT",
    [8]  = "SEND_ERROR",
    [9]  = "MESSAGE",
    [10] = "ACK",
    [11] = "FLOW",
    [12] = "UNSUBSCRIBE",
    [13] = "SUCCESS",
    [14] = "ERROR",
    [15] = "CLOSE_PRODUCER",
    [16] = "CLOSE_CONSUMER",
    [17] = "PRODUCER_SUCCESS",
    [18] = "PING",
    [19] = "PONG",
    [20] = "REDELIVER_UNACKNOWLEDGED_MESSAGES",
    [21] = "PARTITIONED_METADATA",
    [22] = "PARTITIONED_METADATA_RESPONSE",
    [23] = "LOOKUP",
    [24] = "LOOKUP_RESPONSE",
    [25] = "CONSUMER_STATS",
    [26] = "CONSUMER_STATS_RESPONSE",
    [27] = "REACHED_END_OF_TOPIC",
    [28] = "SEEK",
    [29] = "GET_LAST_MESSAGE_ID",
    [30] = "GET_LAST_MESSAGE_ID_RESPONSE",
    [31] = "ACTIVE_CONSUMER_CHANGE",
    [32] = "GET_TOPICS_OF_NAMESPACE",
    [33] = "GET_TOPICS_OF_NAMESPACE_RESPONSE",
    [34] = "GET_SCHEMA",
    [35] = "GET_SCHEMA_RESPONSE",
    [36] = "AUTH_CHALLENGE",
    [37] = "AUTH_RESPONSE",
    [38] = "ACK_RESPONSE",
    [39] = "GET_OR_CREATE_SCHEMA",
    [40] = "GET_OR_CREATE_SCHEMA_RESPONSE",
    [50] = "NEW_TXN",
    [51] = "NEW_TXN_RESPONSE",
    [52] = "ADD_PARTITION_TO_TXN",
    [53] = "ADD_PARTITION_TO_TXN_RESPONSE",
    [54] = "ADD_SUBSCRIPTION_TO_TXN",
    [55] = "ADD_SUBSCRIPTION_TO_TXN_RESPONSE",
    [56] = "END_TXN",
    [57] = "END_TXN_RESPONSE",
    [58] = "END_TXN_ON_PARTITION",
    [59] = "END_TXN_ON_PARTITION_RESPONSE",
    [60] = "END_TXN_ON_SUBSCRIPTION",
    [61] = "END_TXN_ON_SUBSCRIPTION_RESPONSE",
    [62] = "TC_CLIENT_CONNECT_REQUEST",
    [63] = "TC_CLIENT_CONNECT_RESPONSE",
    [64] = "WATCH_TOPIC_LIST",
    [65] = "WATCH_TOPIC_LIST_SUCCESS",
    [66] = "WATCH_TOPIC_UPDATE",
    [67] = "WATCH_TOPIC_LIST_CLOSE",
    [68] = "TOPIC_MIGRATED",
}

-- Decode a protobuf varint starting at 'offset' in tvb.
-- Returns (value, bytes_consumed), or (nil, 0) on failure.
-- Uses floating-point arithmetic to avoid requiring bitwise ops (Lua 5.1/5.2 compat).
local function decode_varint(tvb, offset)
    local result = 0
    local shift  = 0
    local limit  = math.min(offset + 10, tvb:len())
    for i = offset, limit - 1 do
        local b = tvb(i, 1):uint()
        result = result + (b % 128) * (2 ^ shift)
        shift  = shift + 7
        if b < 128 then
            return math.floor(result), i - offset + 1
        end
    end
    return nil, 0
end

-- Peek at BaseCommand.type (field 1, wire type 0 = varint; tag byte = 0x08).
local function get_command_type(cmd_tvb)
    if cmd_tvb:len() < 2 then return nil end
    if cmd_tvb(0, 1):uint() ~= 0x08 then return nil end
    local val, _ = decode_varint(cmd_tvb, 1)
    return val
end

-- Call the protobuf dissector safely inside pcall so parse errors don't kill us.
local function call_protobuf(pb_type, tvb, pinfo, tree)
    if not protobuf_dissector then return end
    pinfo.private["pb_msg_type"] = "message," .. pb_type
    pcall(function() protobuf_dissector:call(tvb, pinfo, tree) end)
end

-- get_pulsar_length: called by dissect_tcp_pdus to determine PDU length.
-- Wireshark guarantees tvb has at least min_header_size (4) bytes.
local function get_pulsar_length(tvb, pinfo, tree)
    return tvb(0, 4):uint() + 4  -- TOTAL_SIZE value + the 4 bytes for the field itself
end

-- dissect_pulsar_pdu: called by dissect_tcp_pdus for each reassembled PDU.
local function dissect_pulsar_pdu(tvb, pinfo, tree)
    pinfo.cols.protocol = "Pulsar"
    local pdu_len = tvb:len()
    local offset  = 0

    local root = tree:add(pulsar_protocol, tvb())

    -- [TOTAL_SIZE] 4 bytes
    root:add(f_total_size, tvb(offset, 4))
    offset = offset + 4

    -- [CMD_SIZE] 4 bytes
    if pdu_len < offset + 4 then
        root:add_proto_expert_info(ef_too_short)
        return
    end
    local cmd_size = tvb(offset, 4):uint()
    root:add(f_cmd_size, tvb(offset, 4))
    offset = offset + 4

    -- [CMD] cmd_size bytes — protobuf BaseCommand
    if pdu_len < offset + cmd_size then
        root:add_proto_expert_info(ef_too_short)
        return
    end
    local cmd_tvb  = tvb(offset, cmd_size):tvb()
    local cmd_item = root:add(f_cmd, tvb(offset, cmd_size))
    local cmd_type = get_command_type(cmd_tvb)
    local type_name
    if cmd_type then
        type_name = COMMAND_TYPES[cmd_type] or ("TYPE_" .. cmd_type)
        pinfo.cols.info = type_name
        root:append_text(" (" .. type_name .. ")")
    end
    call_protobuf("pulsar.proto.BaseCommand", cmd_tvb, pinfo, cmd_item)
    offset = offset + cmd_size

    -- Simple command with no payload — done
    if offset >= pdu_len then return end

    -- Check for broker entry metadata (magic 0x0e02, protocol v16+)
    if pdu_len >= offset + 2 and tvb(offset, 2):uint() == MAGIC_BROKER_ENTRY then
        root:add(f_magic, tvb(offset, 2)):append_text(" [Broker Entry Metadata]")
        offset = offset + 2
        if pdu_len < offset + 4 then
            root:add_proto_expert_info(ef_too_short)
            return
        end
        local broker_meta_size = tvb(offset, 4):uint()
        root:add(f_broker_meta_size, tvb(offset, 4))
        offset = offset + 4
        if pdu_len < offset + broker_meta_size then
            root:add_proto_expert_info(ef_too_short)
            return
        end
        local broker_meta_tvb  = tvb(offset, broker_meta_size):tvb()
        local broker_meta_item = root:add(f_broker_meta, tvb(offset, broker_meta_size))
        call_protobuf("pulsar.proto.BrokerEntryMetadata", broker_meta_tvb, pinfo, broker_meta_item)
        offset = offset + broker_meta_size
    end

    -- Check for CRC32C checksum magic (0x0e01)
    if pdu_len >= offset + 2 and tvb(offset, 2):uint() == MAGIC_CRC32C then
        root:add(f_magic, tvb(offset, 2)):append_text(" [CRC32C]")
        offset = offset + 2
        if pdu_len < offset + 4 then
            root:add_proto_expert_info(ef_too_short)
            return
        end
        root:add(f_checksum, tvb(offset, 4))
        offset = offset + 4
    end

    -- [METADATA_SIZE] 4 bytes
    if pdu_len < offset + 4 then
        root:add_proto_expert_info(ef_too_short)
        return
    end
    local metadata_size = tvb(offset, 4):uint()
    root:add(f_metadata_size, tvb(offset, 4))
    offset = offset + 4

    -- [METADATA] metadata_size bytes — protobuf MessageMetadata
    if pdu_len < offset + metadata_size then
        root:add_proto_expert_info(ef_too_short)
        return
    end
    local metadata_tvb  = tvb(offset, metadata_size):tvb()
    local metadata_item = root:add(f_metadata, tvb(offset, metadata_size))
    call_protobuf("pulsar.proto.MessageMetadata", metadata_tvb, pinfo, metadata_item)
    offset = offset + metadata_size

    -- [PAYLOAD] remaining bytes
    if offset < pdu_len then
        root:add(f_payload, tvb(offset, pdu_len - offset))
    end
end

pulsar_protocol.dissector = function(tvb, pinfo, tree)
    dissect_tcp_pdus(tvb, tree, 4, get_pulsar_length, dissect_pulsar_pdu)
    return tvb:len()
end

pulsar_protocol.prefs.port = Pref.uint("Pulsar TCP port", 6650)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(pulsar_protocol.prefs.port, pulsar_protocol)
