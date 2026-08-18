# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4421_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4421_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 152-192 of the vulnerable file.


	const uint8_t *packet_type = buffer->data;

	switch (*packet_type) {
	case PACKET_DATA:
		if (!fastd_peer_is_established(peer) || !fastd_peer_address_equal(&peer->local_address, local_addr)) {
			fastd_buffer_free(buffer);

			if (!backoff_unknown(remote_addr)) {
				pr_debug("unexpectedly received payload data from %P[%I]", peer, remote_addr);
				conf.protocol->handshake_init(sock, local_addr, remote_addr, NULL);
			}
			return;
		}

		conf.protocol->handle_recv(peer, buffer);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(sock, local_addr, remote_addr, peer, buffer);
	}
}

/** Determines if packets from known addresses are accepted */
static inline bool allow_unknown_peers(void) {
	return ctx.has_floating || fastd_allow_verify();
}

/** Handles a packet received from an unknown address */
static inline void handle_socket_receive_unknown(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_buffer_t *buffer) {
	const uint8_t *packet_type = buffer->data;

	switch (*packet_type) {
	case PACKET_DATA:
		fastd_buffer_free(buffer);

		if (!backoff_unknown(remote_addr)) {
			pr_debug("unexpectedly received payload data from unknown address %I", remote_addr);
			conf.protocol->handshake_init(sock, local_addr, remote_addr, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -169,6 +169,11 @@
 
 	case PACKET_HANDSHAKE:
 		fastd_handshake_handle(sock, local_addr, remote_addr, peer, buffer);
+		break;
+
+	default:
+		fastd_buffer_free(buffer);
+		pr_debug("received packet with invalid type from %P[%I]", peer, remote_addr);
 	}
 }
 
@@ -195,6 +200,11 @@
 
 	case PACKET_HANDSHAKE:
 		fastd_handshake_handle(sock, local_addr, remote_addr, NULL, buffer);
+		break;
+
+	default:
+		fastd_buffer_free(buffer);
+		pr_debug("received packet with invalid type from unknown address %I", remote_addr);
 	}
 }
 
```
