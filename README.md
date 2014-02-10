Gophernet
=========

A mesh network inspired by whispering gophers.

Wire Protocol
-------------

*Header*
```
+-------+---------+------+-----------+----------+----------+------------+
| Magic | Version | Hops | ECDSA     | Sender   | Encoding | Payload    |
| Byte  | Field   | Left | Signature | UUID     | Field    | Size (int) |
+-------+---------+------+-----------+----------+----------+------------+
| byte  | int8    | int8 | 64 bytes  | 16 bytes | int8     | int32      |
+-------+---------+------+-----------+----------+----------+------------+
|       |         | drop | 32B for r | UUID4    | 0 = JSON |            |
|  'g'  |    1    | when |           | linked to| 1=Snappy | Big endian |
|       |         | zero | 32B for s | pubkey   |   + JSON |            |
+-------+---------+------+-----------+----------+----------+------------+
```

*Versions*

Version 1 of gophernet uses ECDSA-with-SHA1 message signing/verification. The
hash is over the concatenation of the Sender UUID, Encoding byte, Payload Size,
and payload.

Negative versions (high bit set) are reserved for private test networks and
should be ignored.

Version 0 is reserved for heartbeat packets.

*Heartbeat packet*

Just the magic byte followed by all 0 bytes for the rest of the header.

**Payload**

Version 1 uses an extensible JSON payload designed to be extensible
without breaking backward compatibility.

*Standard fields*

* ``type``: Speficies message type (e.g.: pubkey, chat)
* ``ts``: Timestamp message was sent at in RFC3339 format
* ``id``: Unique 

*Key announcment*
```json
{
    "type": "pubkey",
    "from": "36 hex character UUID (with dashes)",
    "nick": "nickname to associate with pubkey and uuid",
    "ecdsa.P256": {
        "x": "hex encoded X component",
        "y": "hex encoded Y component",
    }
}
```

*Chat message*
```json
{
    "nick": "<string>",
    "msg":  "<string>"
}
```
