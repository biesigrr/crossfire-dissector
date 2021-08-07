-------------------------------------------------------------------------------
--
-- author: Biesi Grr
-- This code is distributed under the GPLv2 License
--
-------------------------------------------------------------------------------
crossfire_protocol = Proto("CrossFire", "CrossFire Protocol")

packet_length = ProtoField.uint16("crossfire.packet.length", "Packet Length", base.DEC)
packet_op = ProtoField.uint8("crossfire.packet.op", "OpCode", base.DEC)
packet_data = ProtoField.bytes("crossfire.packet.data", "Data", base.NONE)

crossfire_protocol.fields = { 
    packet_length,
    packet_op,
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
    subtree:add(packet_op, tvb(3, 1))
    subtree:add(packet_op, tvb(4, 1))
    subtree:add(packet_op, tvb(5, 1))
    subtree:add(packet_data, tvb(8, tvb:len() - 9))

    op1 = tvb(3, 1):uint()
    op2 = tvb(4, 1):uint()
    op3 = tvb(5, 1):uint()

    if (0 == op1 and 1 == op2 and 0 == op3) then
        -- Parse server list and register present ports
        -- for our dissector protocol 
        server_count = tvb(8 + 45, 2):le_uint()
        for i=1,server_count,1 do
            port_offset = 8 + 15 + i * 89
            port = tvb(port_offset, 4):le_uint()
            
            DissectorTable.get("tcp.port"):add(port, crossfire_protocol)
        end
    end
end 

function crossfire_protocol.dissector(tvb, pinfo, tree)

    dissect_tcp_pdus(tvb, tree, 3, get_crossfire_packet_length, crossfire_protocol_dissect_reassebmled)

end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(13008, crossfire_protocol)