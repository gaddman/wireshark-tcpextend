# wireshark-tcpextend
A Wireshark LUA script to display some additional TCP information.

This is a post-dissector script which adds a new tree to the Wireshark view, _TCP extended info_.

All statistics are referenced to the sending node, and displayed on both sent and received packets.
* **bsp**: bytes sent since the last push flag.
* **bif**: bytes in flight. This will normally equal the built-in `tcp.analysis.bytes_in_flight`, however it is also displayed on the ACK packets.
* **max_tx**: maximum size packet the server can send, equal to the client's receive window minus the server's bytes in flight.
* **pba**: number of packets between this ACK and the packet it ACKs (equal to the builtin `frame.number` minus `tcp.analysis.acks_frame`). TODO: this should be count of how many data packets were received, it is currently everything, even non-TCP.

## Usage:
Copy to your Wireshark plugins folder, on Windows 8 and later this is `C:\Users\<username>\AppData\Roaming\Wireshark\plugins`. You may need to create the folder first.

Now when viewing a capture in Wireshark you'll see an extra line in the protocol list, _TCP extended info_. These can be filtered and displayed as columns, just like any native Wireshark protocol information.

**Additional protocol tree:**
![*Screenshot of additional protocol tree](https://cloud.githubusercontent.com/assets/1311209/8146049/bd2d29f8-1277-11e5-8b45-4f7c071ff8ff.png)

**Additional columns (highlighted):**
![Screenshot of additional columns](https://cloud.githubusercontent.com/assets/1311209/8146105/c0498890-127a-11e5-8f7f-003e927dac23.png)

## Compatibility
Tested on Wireshark 1.12.5 under Windows 8.1. It may work with other OS and versions, if it doesn't submit an issue or pull request.

## Known limitiations:
* Any TCP errors (eg retransmissions, OOO) are not correctly handled.
* When the columns in Wireshark are changed in any way (added/removed/renamed), the calculations may get stuffed up, in which case you'll need to restart Wireshark.
