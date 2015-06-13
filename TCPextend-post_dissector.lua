-- Wireshark post-dissector to calculate some additional TCP information
--
-- All statistics are referenced to a single node, usually the sender, and displayed on both sent and received packets.
-- bif:		bytes in flight. This will normally equal the built-in tcp.analysis.bytes_in_flight, however it is 
--			also displayed on the ACK packets.
-- max_tx:	maximum size packet the server can send, equal to the client's receive window minus the server's bytes in flight.
-- bsp:		bytes sent since the last push flag.
-- pba:		number of packets between this ACK and the packet it ACKs (equal to the builtin frame.number minus tcp.analysis.acks_frame)
--			TODO: this should be count of how many data packets were received, it is currently everything, even non-TCP.
--
-- Chris Gadd
-- https://github.com/gaddman/wireshark-tcpextend
-- v0.4-20150614
--
-- Known limitiations:
-- Any TCP errors (eg retransmissions, OOO) are not correctly handled

-- declare some Fields to be read
local tcp_len_f = Field.new("tcp.len")
local tcp_ack_f = Field.new("tcp.ack")
local tcp_len_f = Field.new("tcp.len")
local tcp_push_f = Field.new("tcp.flags.push")
local tcp_seq_f = Field.new("tcp.seq")
local tcp_stream_f = Field.new("tcp.stream")
local tcp_win_f = Field.new("tcp.window_size")
local tcp_src_f = Field.new("tcp.srcport")
local tcp_dst_f = Field.new("tcp.dstport")
local tcp_ack_frm_f = Field.new("tcp.analysis.acks_frame")

-- declare (pseudo) protocol
local TCPextend_proto = Proto("TCPextend","Extended TCP information")
-- create the fields for this "protocol". These probably shouldn't all be 32 bit integers.
local bif_F = ProtoField.int32("TCPextend.bif","Bytes in Flight")
local max_tx_F = ProtoField.int32("TCPextend.max_tx","Max tx bytes")
local bsp_F = ProtoField.int32("TCPextend.bsp","Bytes since PSH")
local pba_F = ProtoField.int32("TCPextend.pba","Packets before ACK")
-- add the fields to the protocol
TCPextend_proto.fields = {bif_F, max_tx_F, bsp_F, pba_F}
-- register protocol as a postdissector
register_postdissector(TCPextend_proto)

-- variables to persist across all packets
local tcpextend_stats = {}
-- per stream
tcpextend_stats.client_port = {}
tcpextend_stats.server_port = {}
tcpextend_stats.client_win = {}
tcpextend_stats.server_win = {}
tcpextend_stats.client_bsp = {}
tcpextend_stats.server_bsp = {}
tcpextend_stats.client_ack = {}
tcpextend_stats.server_ack = {}
tcpextend_stats.client_len = {}
tcpextend_stats.server_len = {}
-- per packet
tcpextend_stats.bif = {}
tcpextend_stats.bsp = {}
tcpextend_stats.txb = {}
tcpextend_stats.pba = {}
   
-- function to "postdissect" each frame
function TCPextend_proto.dissector(extend,pinfo,tree)

	local tcp_len = tcp_len_f()
	if tcp_len then    -- seems like it should filter out TCP traffic. Maybe there's a way like taps to register the dissector with a filter?
		tcp_len = tcp_len.value
		local pkt_no = tostring(pinfo.number) -- warning, this will become a large array (of 32bit integers) if lots of packets
		local tcp_stream = tcp_stream_f().value
		local tcp_ack = tcp_ack_f().value
		local tcp_push = tcp_push_f().value
		local tcp_win = tcp_win_f().value
		local tcp_seq = tcp_seq_f().value
		local tcp_srcport = tcp_src_f().value
		local tcp_dstport = tcp_dst_f().value

		if not pinfo.visited then
	
			-- set initial values if this stream not seen before            
			if not tcpextend_stats.client_port[tcp_stream] then
				tcpextend_stats.client_port[tcp_stream] = tcp_srcport  -- assuming first packet we see is client to server
				tcpextend_stats.server_port[tcp_stream] = tcp_dstport
				tcpextend_stats.client_win[tcp_stream] = 0
				tcpextend_stats.server_win[tcp_stream] = 0
				tcpextend_stats.client_bsp[tcp_stream] = 0
				tcpextend_stats.server_bsp[tcp_stream] = 0
				tcpextend_stats.client_ack[tcp_stream] = 0
				tcpextend_stats.server_ack[tcp_stream] = 0
				tcpextend_stats.client_len[tcp_stream] = 0
				tcpextend_stats.server_len[tcp_stream] = 0
			end
			-- declare variables local to this packet
			local cbsp = 0
			local sbsp = 0
			local cbif = 0
			local sbif = 0
			local ctxb = 0
			local stxb = 0
			
			-- calculate depending on which direction this packet is going
			if tcp_srcport == tcpextend_stats.server_port[tcp_stream] then
				-- from server
				-- set current, and then calculate new bytes since last push
				sbsp = tcpextend_stats.server_bsp[tcp_stream] + tcp_len
				cbsp = tcpextend_stats.client_bsp[tcp_stream]
				if tcp_push == true then
					tcpextend_stats.server_bsp[tcp_stream] = 0
				else
					tcpextend_stats.server_bsp[tcp_stream] = tcpextend_stats.server_bsp[tcp_stream] + tcp_len
				end
				-- txb = receive window - _current_ BiF
				stxb = tcpextend_stats.client_win[tcp_stream] - (tcpextend_stats.server_len[tcp_stream] - tcpextend_stats.client_ack[tcp_stream] + 1)
				ctxb = tcpextend_stats.server_win[tcp_stream] - (tcpextend_stats.client_len[tcp_stream] - tcpextend_stats.server_ack[tcp_stream] + 1)
				-- set/calculate new persistent values
				tcpextend_stats.server_len[tcp_stream] = tcpextend_stats.server_len[tcp_stream] + tcp_len
				tcpextend_stats.server_ack[tcp_stream] = tcp_ack
				tcpextend_stats.server_win[tcp_stream] = tcp_win
			elseif tcp_srcport == tcpextend_stats.client_port[tcp_stream] then
				-- from client
				-- set current, and then calculate new bytes since last push
				cbsp = tcpextend_stats.client_bsp[tcp_stream] + tcp_len
				sbsp = tcpextend_stats.server_bsp[tcp_stream]
				if tcp_push == true then
					tcpextend_stats.client_bsp[tcp_stream] = 0
				else
					tcpextend_stats.client_bsp[tcp_stream] = tcpextend_stats.client_bsp[tcp_stream] + tcp_len
				end
				-- txb = receive window - _current_ BiF
				ctxb = tcpextend_stats.server_win[tcp_stream] - (tcpextend_stats.client_len[tcp_stream] - tcpextend_stats.server_ack[tcp_stream] + 1)
				stxb = tcpextend_stats.client_win[tcp_stream] - (tcpextend_stats.server_len[tcp_stream] - tcpextend_stats.client_ack[tcp_stream] + 1)
				-- set/calculate new persistent values
				tcpextend_stats.client_len[tcp_stream] = tcpextend_stats.client_len[tcp_stream] + tcp_len
				tcpextend_stats.client_ack[tcp_stream] = tcp_ack
				tcpextend_stats.client_win[tcp_stream] = tcp_win
			end			
			
			-- calculate new bytes in flight
			cbif = tcpextend_stats.client_len[tcp_stream] - tcpextend_stats.server_ack[tcp_stream] + 1
			sbif = tcpextend_stats.server_len[tcp_stream] - tcpextend_stats.client_ack[tcp_stream] + 1
			
			-- try to guess which node is the sender, and display stats based on that
			-- the '=' comparison in case they're both 0 favours download traffic
			if sbif >= cbif then
				-- server is sending data in this stream
				tcpextend_stats.bif[pkt_no] = sbif
				tcpextend_stats.bsp[pkt_no] = sbsp
				tcpextend_stats.txb[pkt_no] = stxb
			else
				-- client is sending data in this stream
				tcpextend_stats.bif[pkt_no] = cbif
				tcpextend_stats.bsp[pkt_no] = cbsp
				tcpextend_stats.txb[pkt_no] = ctxb
			end
			
			if tcp_ack then
				tcpextend_stats.pba[pkt_no] = pkt_no - tcp_ack_frm_f().value
			end

		end	-- if packet not visited

		-- packet processed, output to tree
		local subtree = tree:add(TCPextend_proto,"TCP extended info")
		subtree:add(bsp_F,tcpextend_stats.bsp[pkt_no]):set_generated()
		subtree:add(bif_F,tcpextend_stats.bif[pkt_no]):set_generated()
		subtree:add(max_tx_F,tcpextend_stats.txb[pkt_no]):set_generated()
		if tcpextend_stats.pba[pkt_no] then
			subtree:add(pba_F,tcpextend_stats.pba[pkt_no]):set_generated()
		end
	end	-- if a TCP packet
end
