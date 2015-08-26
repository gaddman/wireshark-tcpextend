# wireshark-tcpextend
A Wireshark LUA script to display some additional TCP information.

This is a post-dissector script which adds a new tree to the Wireshark view, _TCP extended info_.

All statistics, except delta and ack_sz, are referenced to the sending node, and displayed on both sent and received packets.
* **bsp**: bytes sent since the last push flag.
* **bif**: bytes in flight. This will normally equal the built-in `tcp.analysis.bytes_in_flight`, however it is also displayed on the ACK packets.
* **max_tx**: maximum size packet the server can send, equal to the client's receive window minus the server's bytes in flight.
* **pba**: number of packets between this ACK and the packet it ACKs (equal to the builtin `frame.number` minus `tcp.analysis.acks_frame`). TODO: this should be count of how many data packets were received, it is currently everything, even non-TCP.
* **delta**: time since the previous packet was transmitted. Unlike the builtin time delta which is relative to the previous displayed packet, this is relative to the previous packet from the matching sender.
* **ack_sz**: size of the segment(s) this ACK is ACKing.
* **ip_inc**: incremental value of the IP ID field, ie how much bigger (or smaller) than the previous packet. Useful for spotting out of order packets in situations where the IP ID increments by 1 each packet. If Large Segment Offload is running on the server then expect to see frequent large negative values.

## Usage:
Copy to your Wireshark plugins folder, on Windows 8 and later this is `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`. You may need to create the folder first.

Now when viewing a capture in Wireshark you'll see an extra line in the protocol list, _TCP extended info_. These can be filtered and displayed as columns, just like any native Wireshark protocol information.

**Additional protocol tree:**
![*Screenshot of additional protocol tree](https://cloud.githubusercontent.com/assets/1311209/9489018/001b6cf4-4c32-11e5-8c1e-2444d5d148d9.png)

**Additional columns (highlighted):**
![Screenshot of additional columns](https://cloud.githubusercontent.com/assets/1311209/9489153/fe884e6a-4c32-11e5-858c-17efdf52c09a.png)

## Compatibility
Tested on Wireshark 1.12.7 under Windows 8.1. It may work with other OS and versions, if it doesn't submit an issue or pull request.

## Known limitiations:
* PBA counts all packets, not just TCP packets
