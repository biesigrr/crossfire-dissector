-------------------------------------------------------------------------------
--
-- author: Biesi Grr
-- This code is distributed under the GPLv2 License
--
-------------------------------------------------------------------------------
crossfire_protocol = Proto("CrossFire", "CrossFire Protocol")

packet_length = ProtoField.uint16("crossfire.packet.length", "Packet Length", base.DEC)
packet_op_group = ProtoField.uint8("crossfire.packet.op.group", "OpCode Group", base.DEC)
packet_op_action = ProtoField.uint16("crossfire.packet.op.action", "OpCode Action", base.DEC)
packet_data = ProtoField.bytes("crossfire.packet.data", "Data", base.NONE)

crossfire_protocol.fields = { 
    packet_length,
    packet_op_group,
    packet_op_action,
    packet_data
}

function get_crossfire_packet_length(tvb, pinfo, offset)

    return tvb(offset + 1, 2):le_uint() + 9

end

function crossfire_protocol_dissect_reassebmled(tvb, pinfo, tree)

    length = tvb:len()
    if 0 == length then return end

    pinfo.cols.protocol = crossfire_protocol.name

    local subtree = tree:add(crossfire_protocol, tvb(), "CrossFire Packet")

    subtree:add_le(packet_length, tvb(1, 2))
    subtree:add(packet_op_group, tvb(3, 1))
    subtree:add_le(packet_op_action, tvb(4, 2))
    subtree:add(packet_data, tvb(8, tvb:len() - 9))

end 

function crossfire_protocol.dissector(tvb, pinfo, tree)

    dissect_tcp_pdus(tvb, tree, 3, get_crossfire_packet_length, crossfire_protocol_dissect_reassebmled)

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(10008, crossfire_protocol)