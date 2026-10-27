These five protocol templates come from the MIT-licensed project
[1936-zero/ecloud-cmsszte-alive](https://github.com/1936-zero/ecloud-cmsszte-alive/tree/dff401845f41826de51030909ee572ebfb672791/assets/templates).
The license is retained in the parent directory's LICENSE.

Reference-specific addresses, machine ID and ticket bytes are cleared in these copies.
They contain protocol framing, not this installation's credentials. Desktop address,
ports, machine ID and short-lived ticket are replaced in memory for every connection.
No connection string is written to disk.

The heartbeat receiver uses the observed 19-byte CMSSZTE message header and handles
fragmentation, coalesced messages and channel closure. The reference's optional
16-byte-header agent nudge is deliberately omitted: on the verified desktop it
desynchronizes outgoing messages and the server closes the channel after about
36 seconds. The server already sends 0x74 heartbeats without that nudge.
