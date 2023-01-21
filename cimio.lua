-------------------------------------------------------------------------------
-- Lua Dissector for Aspentech Cim-IO protocol
-- Author: Jean-Noel Meurisse
-- Copyright (c) 2020, Jean-Noel Meurisse
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--


-- configurable default_settings
local default_settings = {
    ports = { 10000,   -- DLGP (Device Logical Gateway Program) port
              10001,   -- Scanner port
              10002,   -- Store port
              10003 }, -- Forward port
    heuristic_enabled = false,     -- Protocol heuristic (experimental)
    decoder_enabled   = false      -- Data decoder enabled
}

local message_type = {
    [1] = "REQUEST",
    [2] = "REPLY",
    [3] = "NOTIFY"
}

local transaction_type = {
    [1] = "GET",
    [2] = "GETHIST",
    [3] = "PUT",
    [4] = "DECL",
    [5] = "CANC",
    [6] = "UNDEF",
    [7] = "SHUT",
    [8] = "LOGBLK",
    [9] = "FMTBLK",
    [10] = "LOGMSG",
    [11] = "UNS",
    [12] = "CONNECT",
    [13] = "DISCONNECT",
    [14] = "FMTSTS",
    [15] = "MSG",
    [16] = "STOPGET",
    [17] = "ACK",
    [18] = "STOPPUT",
    [19] = "PING",
    [20] = "START_SERVER",
    [21] = "STOP_SERVER",
    [22] = "GET_SERVER_STATUS",
    [24] = "GET_SERVER_CONFIGURATION",
    [25] = "ADD_SERVER",
    [26] = "MODIFY_SERVER_CONFIGURATION",
    [27] = "REMOVE_SERVER",
    [28] = "SET_LOGICAL_DEVICE",
    [29] = "GET_MGMT_PARAMS",
    [30] = "SET_MGMT_PARAMS",
    [31] = "REJECT",
    [32] = "DEL_LOGICAL_DEVICE",
    [33] = "REMOVE_SF_SERVICES",
    [34] = "REMOVE_TCPIP_SERVICE",
    [35] = "WCIDFY"
}

local request_type = {
    [0] = "SYNC",
    [1] = "ASYNC",
    [2] = "NOREP"
}

-- CIMIO Data Types
local CIMIO_REAL   = 1  -- floating point single precision
local CIMIO_SHORT  = 2  -- short integer
local CIMIO_ASCII  = 3  -- ascii string
local CIMIO_LONG   = 4  -- long integer
local CIMIO_DOUBLE = 5  -- floating point double precision
local CIMIO_TIME   = 6  -- absolute time
local CIMIO_STRUCT = 7  -- structure
local CIMIO_INVDT  = -1 -- Invalid data type

local data_type = {
    [CIMIO_INVDT]  = "invalid",
    [CIMIO_REAL]   = "real",
    [CIMIO_SHORT]  = "short",
    [CIMIO_ASCII]  = "ascii",
    [CIMIO_LONG]   = "long",
    [CIMIO_DOUBLE] = "double",
    [CIMIO_TIME]   = "time",
    [CIMIO_STRUCT] = "struct"
}


-- Create Proto object
local cimio_proto = Proto("cimio", "CimIO Protocol")

-- CimIO protocol header's fields
local cimio_hdr_fields = {
    chksum      = ProtoField.uint16("cimio.checksum",  "checksum   ", base.HEX),
    msg_len     = ProtoField.uint32("cimio.msglen",    "msglen     ", base.DEC),
    trans_num   = ProtoField.uint32("cimio.transnum",  "transnum   ", base.DEC),
    msg_type    = ProtoField.uint32("cimio.msgtype",   "msgtype    ", base.RANGE_UNIT, message_type),
    trans_type  = ProtoField.uint32("cimio.transtype", "transtype  ", base.RANGE_UNIT, transaction_type),
    trans_prio  = ProtoField.uint32("cimio.priority",  "priority   ", base.DEC),
    encoding1   = ProtoField.uint32("cimio.encoding1", "encoding1  ", base.DEC),
    encoding2   = ProtoField.uint32("cimio.encoding2", "encoding2  ", base.DEC),
    tplt_count  = ProtoField.uint32("cimio.tpltcount", "tplt count ", base.DEC),
    req_routing = ProtoField.bytes("cimio.request_routing"),
    msg_routing = ProtoField.bytes("cimio.message_routing"),
    data_tplt   = ProtoField.bytes("cimio.template"),
    data        = ProtoField.bytes("cimio.data")
}

-------------------------------------------------------------------------------
--- A convenient function that returns a default value if value is nil
local function ifnil(value, default_value)
    return value or default_value
end

-------------------------------------------------------------------------------
--- Returns the cimio message and transaction type
local function format_cimio_info(msgtype, trntype)
    local msg_str = ifnil(message_type[msgtype], "?")
    local trn_str = ifnil(transaction_type[trntype], "?")

    return string.format("CIMIO, %s %s", trn_str, msg_str)
end

------------------------------------------------------------------------------
--- Converts a cimio data type to a string
local function format_cimio_dtype(dtype)
    return ifnil(data_type[dtype], tostring(dtype))
end

------------------------------------------------------------------------------
--- Formats a number of occurrences
local function format_cimio_nbocc(nbocc)
    if nbocc > 1 then
        return string.format("[%d]", nbocc)
    else
        return ""
    end
end

------------------------------------------------------------------------------
--- Formats a cimio value to a string
local function format_cimio_dvalue(dtplt_node, tvb_data, little_endian)
    local values = {}

    if little_endian then
        for idx = 0, dtplt_node.nbocc - 1 do
            local data = tvb_data:range(idx * dtplt_node.length, dtplt_node.length)
            if (dtplt_node.dtype == CIMIO_SHORT) or (dtplt_node.dtype == CIMIO_LONG) then
                table.insert(values, tostring(data:le_int()))
            elseif (dtplt_node.dtype == CIMIO_REAL) or (dtplt_node.dtype == CIMIO_DOUBLE) then
                table.insert(values, tostring(data:le_float()))
            elseif dtplt_node.dtype == CIMIO_ASCII then
                table.insert(values, data:string())
            elseif dtplt_node.dtype == CIMIO_TIME then
                table.insert(values, tostring(data:le_int()))
            else
                table.insert(values, "?")
            end
        end
    else
        for idx = 0, dtplt_node.nbocc - 1 do
            local data = tvb_data:range(idx * dtplt_node.length, dtplt_node.length)
            if (dtplt_node.dtype == CIMIO_SHORT) or (dtplt_node.dtype == CIMIO_LONG) then
                table.insert(values, tostring(data:int()))
            elseif (dtplt_node.dtype == CIMIO_REAL) or (dtplt_node.dtype == CIMIO_DOUBLE) then
                table.insert(values, tostring(data:float()))
            elseif dtplt_node.dtype == CIMIO_ASCII then
                table.insert(values, data:string())
            elseif dtplt_node.dtype == CIMIO_TIME then
                table.insert(values, tostring(data:int()))
            else
                table.insert(values, "?")
            end
        end
    end

    local values_list = table.concat(values, ", ")
    if dtplt_node.nbocc > 1 then
        values_list = "[" .. values_list .. "]"
    end

    return values_list
end

-------------------------------------------------------------------------------
--- Formats a process identifier
local function format_cimio_processid(header, node, service)
    return string.format("%s node=%s service=%s", header, node, service)
end

-------------------------------------------------------------------------------
--- This function decodes a data template item and returns a template structure
--- having the following attributes
---         index   : position in the template array (was used during debugging)
---         dtype   : application data type
---         ddttype : device data type
---         length  : length in bytes
---         nbocc   : number of occurrences
---         tvb     : the portion of the packet containing this template
---         struct  : a place holder to store the structure definition when dtype=7
---
local function decode_cimio_dtemplate(idx, dtpl_tvb, little_endian)
    if little_endian then
        -- template attributes are stored with little endian convention
        return {
            index = idx,
            dtype = dtpl_tvb:range(0, 2):le_int(),
            ddtype = dtpl_tvb:range(2, 2):le_int(),
            length = dtpl_tvb:range(4, 4):le_int(),
            nbocc = dtpl_tvb:range(8, 4):le_int(),
            tvb = dtpl_tvb,
            struct = nil
        }
    else
        -- template attributes are stored with big endian convention
        return {
            index = idx,
            dtype = dtpl_tvb:range(0, 2):int(),
            ddtype = dtpl_tvb:range(2, 2):int(),
            length = dtpl_tvb:range(4, 4):int(),
            nbocc = dtpl_tvb:range(8, 4):int(),
            tvb = dtpl_tvb,
            struct = nil
        }
    end
end


-------------------------------------------------------------------------------
--- This function checks if a data template item is valid. The function returns
--- true if the template has a positive size
local function check_cimio_dtemplate(dtplt_node)
    return (dtplt_node.nbocc >= 1) and (dtplt_node.length > 0)
end



local function debug_output_dtemplate(dtplt_node)
    debug(string.format("   idx=%d dtype=%d ddtype=%d len=%d nbocc=%d tvbuflen=%d",
            dtplt_node.index,
            dtplt_node.dtype,
            dtplt_node.ddtype,
            dtplt_node.length,
            dtplt_node.nbocc,
            dtplt_node.tvb:len())
    )
end

-------------------------------------------------------------------------------
--- Decodes the template array
---
local function decode_cimio_dtemplate_buffer(dtplt_tvb, little_endian)
    local idx = 0           -- cursor over the flattened templates tree
    local unflatten_tree

    unflatten_tree = function(len)
        local tree = {}
        local jdx = 0

        while (idx < dtplt_tvb:len() / 12) and (jdx < len) do
            idx = idx + 1
            jdx = jdx + 1

            -- decode a single template entry
            local dtplt_node = decode_cimio_dtemplate(idx, dtplt_tvb:range((idx - 1) * 12, 12), little_endian)

            if (dtplt_node.dtype == CIMIO_STRUCT) then
                -- when the data type is a structure, the content of the structure is stored in
                -- subsequent template entries. The number of entries is stored in the length
                -- attribute.
                dtplt_node.struct = unflatten_tree(dtplt_node.length)
            end

            -- debug_output_dtemplate(dtplt_node)
            table.insert(tree, dtplt_node)
        end

        return tree
    end

    return unflatten_tree(dtplt_tvb:len() / 12)
end

-------------------------------------------------------------------------------
--- Add the data template structure to the specified sub tree
---
local function add_cimio_dtemplate_tree(subtree, dtplt_tree)
    local add_dtemplate_tree

    add_dtemplate_tree = function(dtplt_subtree, level)
        local indent = string.rep("   ", level)

        for idx = 1, #dtplt_subtree do
            local dtplt_node = dtplt_subtree[idx]

            if dtplt_node.dtype == CIMIO_STRUCT then
                subtree:add(dtplt_node.tvb, string.format("%sstruct {", indent))
                add_dtemplate_tree(dtplt_node.struct, level + 1)
                subtree:add(string.format("%s}%s", indent, format_cimio_nbocc(dtplt_node.nbocc)))

            else
                local info = string.format("%s%s*%d%s",
                        indent,
                        format_cimio_dtype(dtplt_node.dtype),
                        dtplt_node.length,
                        format_cimio_nbocc(dtplt_node.nbocc))
                subtree:add(dtplt_node.tvb, info)
            end
        end
    end

    add_dtemplate_tree(dtplt_tree, 0)
end

-------------------------------------------------------------------------------
--- This function computes the data size occupied by a given template
---
local function compute_cimio_dtemplate_size(dtplt_node)
    local size = 0
    if dtplt_node.dtype == CIMIO_STRUCT then
        local struct_size = 0
        for i = 1, #dtplt_node.struct do
            struct_size = struct_size + compute_cimio_dtemplate_size(dtplt_node.struct[i])
        end
        size = struct_size * dtplt_node.nbocc
    else
        size = dtplt_node.length * dtplt_node.nbocc
    end

    return size
end

-------------------------------------------------------------------------------
--- Add the data array to the specified sub tree
---
local function add_cimio_data_array(subtree, dtplt_tree, data_tvb, little_endian)
    local offset = 0
    local add_data_array

    add_data_array = function(dtplt_subtree, level)
        local indent = string.rep("   ", level)

        for idx = 1, #dtplt_subtree do
            local dtplt_node = dtplt_subtree[idx]

            local node_size = compute_cimio_dtemplate_size(dtplt_node)
            if (not check_cimio_dtemplate(dtplt_node)) then
                -- invalid template
                subtree:add("template is invalid")
            else
                local node_data = data_tvb:range(offset, node_size)

                if dtplt_node.dtype == CIMIO_STRUCT then
                    local saved_offset = offset
                    if (dtplt_node.nbocc == 1) then
                        subtree:add(node_data, string.format("%sstruct {", indent))
                        add_data_array(dtplt_node.struct, level + 1)
                        subtree:add(node_data, string.format("%s}%s", indent, format_cimio_nbocc(dtplt_node.nbocc)))
                    else
                        for jdx = 1, dtplt_node.nbocc do
                            subtree:add(node_data, string.format("%s[%d of %d] struct {", indent, jdx, dtplt_node.nbocc))
                            add_data_array(dtplt_node.struct, level + 1)
                            subtree:add(node_data, string.format("%s}", indent))
                        end
                    end

                    offset = saved_offset + node_size
                else
                    local info = string.format("%s%s*%d%s = %s",
                            indent,
                            format_cimio_dtype(dtplt_node.dtype),
                            dtplt_node.length,
                            format_cimio_nbocc(dtplt_node.nbocc),
                            format_cimio_dvalue(dtplt_node, node_data, little_endian))
                    subtree:add(node_data, info)

                    offset = offset + node_size
                end
            end

        end
    end

    add_data_array(dtplt_tree, 0)
end

-------------------------------------------------------------------------------
--- Add cimio request routing to the specified sub tree
---
local function add_cimio_request_routing(subtree, routing_tvb)
    local tree = subtree:add(cimio_hdr_fields.req_routing, routing_tvb):set_text("request routing")

    -- extract service and node names
    local r = {}    -- data range
    local s = {}    -- strings
    for i = 1, 4 do
        r[i] = routing_tvb:range((i - 1) * 32, 32)
        s[i] = r[i]:string()
    end

    tree:add(routing_tvb:range(0, 64), format_cimio_processid("request src :", s[1], s[2]))
    tree:add(routing_tvb:range(64, 64), format_cimio_processid("reply dst   :", s[3], s[4]))
end

-------------------------------------------------------------------------------
--- Add cimio message routing to the specified tree
---
local function add_cimio_message_routing(subtree, routing_tvb)
    local tree = subtree:add(cimio_hdr_fields.msg_routing, routing_tvb):set_text("message routing")

    -- extract service and node names
    local r = {}    -- data range
    local s = {}    -- strings
    for i = 1, 4 do
        r[i] = routing_tvb:range((i - 1) * 32, 32)
        s[i] = r[i]:string()
    end

    tree:add(routing_tvb:range(0, 64), format_cimio_processid("message src :", s[1], s[2]))
    tree:add(routing_tvb:range(64, 64), format_cimio_processid("message dst :", s[3], s[4]))
end

-------------------------------------------------------------------------------
--- Returns the length of a cimio message in a packet's buffer
---
local CIMIO_LEN_START = 4
local CIMIO_LEN_SIZE = 4
local CIMIO_HEADER_SIZE = 0x124

local function get_cimio_length(tvb, pinfo, offset)
    return tvb:range(offset + CIMIO_LEN_START, CIMIO_LEN_SIZE):uint()
end

-------------------------------------------------------------------------------
--- cimio dissector
---
local function dissect_cimio_pdu(tvb, pinfo, root)
    pinfo.cols.protocol:set("CIMIO")

    local msg_len = get_cimio_length(tvb, pinfo, 0)

    local msg_type_rng = tvb:range(284, 4)
    local trn_type_rng = tvb:range(152, 4)
    local tpl_count_rng = tvb:range(0x120, 4)

    -- We start by adding our protocol to the dissection display tree.
    local subtree = root:add(cimio_proto, msg_len)
    subtree:set_text(format_cimio_info(msg_type_rng:uint(), trn_type_rng:uint()))

    -- CimIO message characteristics
    subtree:add(cimio_hdr_fields.chksum, tvb:range(0x02, 2))
    subtree:add(cimio_hdr_fields.msg_len, tvb:range(CIMIO_LEN_START, CIMIO_LEN_SIZE))
    subtree:add(cimio_hdr_fields.trans_num, tvb:range(0x08, 4))
    subtree:add(cimio_hdr_fields.trans_prio, tvb:range(0x0C, 4))
    subtree:add(cimio_hdr_fields.encoding1,  tvb:range(0x10, 4))
    subtree:add(cimio_hdr_fields.encoding2,  tvb:range(0x14, 4))
    subtree:add(cimio_hdr_fields.msg_type, msg_type_rng)
    subtree:add(cimio_hdr_fields.trans_type, trn_type_rng)
    subtree:add(cimio_hdr_fields.tplt_count, tpl_count_rng)

    -- CimIO message and request routing information
    add_cimio_request_routing(subtree, tvb:range(0x18, 4 * 32))
    add_cimio_message_routing(subtree, tvb:range(0x9C, 4 * 32))

    -- Determine the endianness (le=little endian, be=big endian)
    local encoding = tvb:range(0x14, 4):int()
    local header_be = encoding >= 1
    local data_be = encoding == 2

    -- get the number of template items in the packet header
    local template_count = tpl_count_rng:uint()

    if (template_count > 0) then
        local template_size = 12 * template_count
        local data_size = 0

        if template_size + CIMIO_HEADER_SIZE <= msg_len then
            -- get the data template structure and decode it
            local dtplt_tvb = tvb:range(CIMIO_HEADER_SIZE, template_size)
            local dtplt_tree = decode_cimio_dtemplate_buffer(dtplt_tvb, not header_be)

            -- show the template
            local template_subtree = subtree:add(cimio_hdr_fields.data_tplt, dtplt_tvb):set_text("template")
            add_cimio_dtemplate_tree(template_subtree, dtplt_tree)

            -- compute data payload size
            data_size = compute_cimio_dtemplate_size(dtplt_tree[1])

            -- get the rest of the buffer starting after the template
            local data_tvb = tvb:range(CIMIO_HEADER_SIZE + template_size)
            local data_subtree = subtree:add(cimio_hdr_fields.data, data_tvb)
            if data_size <= data_tvb:len() then
                if cimio_proto.prefs.decoder_enabled then
                    data_subtree:set_text("data")
                    add_cimio_data_array(data_subtree, dtplt_tree, data_tvb, not data_be)
                end
            else
                data_subtree:set_text("data corrupted")
            end
        else
            -- payload is corrupted
            subtree:add(cimio_hdr_fields.data_tplt, tvb:range(CIMIO_HEADER_SIZE)):set_text("template corrupted")
        end
    end

    return msg_len
end


--------------------------------------------------------------------------------
-- Define the CimIO heuristic dissector.
--
local function heuristic_checker(tvb, pinfo, root)
    local is_cimio = false

    -- cimio header delimiter
    local CIMIO_MAGIC_START = 0
    local CIMIO_MAGIC_LEN = 2

    -- 8 bytes are needed to determine if it is a cimio packet
    if cimio_proto.prefs.heuristic
            and (tvb:len() >= 8)
            and (tvb:range(CIMIO_MAGIC_START, CIMIO_MAGIC_LEN):uint() == 0x5A5A)
            and (get_cimio_length(tvb, pinfo, 0) >= CIMIO_HEADER_SIZE) then
        -- dissect our packet
        dissect_cimio_pdu(tvb, pinfo, root)
        is_cimio = true
    end

    return is_cimio
end

--------------------------------------------------------------------------------
-- Define the CimIO protocol
cimio_proto.fields = cimio_hdr_fields

cimio_proto.dissector = function(tvb, pinfo, root)
    return dissect_tcp_pdus(tvb, root, 8, get_cimio_length, dissect_cimio_pdu)
end

-- register the CimIO protocol heuristic
cimio_proto:register_heuristic("tcp", heuristic_checker)

-- Define our preferences
cimio_proto.prefs.port_dlgp       = Pref.uint("DLGP service port", default_settings.port_dlgp)
cimio_proto.prefs.port_sc         = Pref.uint("Scanner service port", default_settings.port_sc)
cimio_proto.prefs.port_st         = Pref.uint("Store service port", default_settings.port_st)
cimio_proto.prefs.port_fw         = Pref.uint("Forward service port", default_settings.port_fw)
cimio_proto.prefs.heuristic       = Pref.bool("Heuristic enabled (experimental)", default_settings.heuristic_enabled)
cimio_proto.prefs.decoder_enabled = Pref.bool("Data decoder enabled", default_settings.decoder_enabled)

local function register_cimio_ports(ports)
    local tcp_port_table = DissectorTable.get("tcp.port")

    for idx = 1, 4 do
        local p = ports[idx]
        if p ~= 0 then
            tcp_port_table:add(p, cimio_proto.dissector)
        end
    end
end

cimio_proto.prefs_changed = function()
    local tcp_port_table = DissectorTable.get("tcp.port")

    -- remove previous port definitions
    for idx = 1, 4 do
        local p = default_settings.ports[idx]
        if p ~= 0 then
            tcp_port_table:remove(p, cimio_proto.dissector)
        end
    end

    default_settings.ports[1] = cimio_proto.prefs.port_dlgp
    default_settings.ports[2] = cimio_proto.prefs.port_sc
    default_settings.ports[3] = cimio_proto.prefs.port_st
    default_settings.ports[4] = cimio_proto.prefs.port_fw

    register_cimio_ports(default_settings.ports)
end

register_cimio_ports(default_settings.ports)
