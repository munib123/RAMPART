# CrossVul Fix Pair: Unintended Proxy or Intermediary ('Confused Deputy') in c
**Pair ID:** 4375_2
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-441
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4375_2`)

## Vulnerability Information & PoC

## Description
Unintended Proxy or Intermediary ('Confused Deputy') - If an attacker cannot directly contact a target, but the product has access to the target, then the attacker can send a request to the product and have it be forwarded to the target.

## Vulnerable Code
```c
Lines 255-295 of the vulnerable file.


static int send_turn_message_to(turn_turnserver *server, ioa_network_buffer_handle nbh, ioa_addr *response_origin, ioa_addr *response_destination)
{
	if(is_rfc5780(server) && nbh && response_origin && response_destination) {
		return server->sm_cb(server->e, nbh, response_origin, response_destination);
	}

	return -1;
}

/////////////////// Peer addr check /////////////////////////////

static int good_peer_addr(turn_turnserver *server, const char* realm, ioa_addr *peer_addr)
{
#define CHECK_REALM(r) if((r)[0] && realm && realm[0] && strcmp((r),realm)) continue

	if(server && peer_addr) {
		if(*(server->no_multicast_peers) && ioa_addr_is_multicast(peer_addr))
			return 0;
		if( !*(server->allow_loopback_peers) && ioa_addr_is_loopback(peer_addr))
			return 0;

		{
			int i;

			if(server->ip_whitelist) {
				// White listing of addr ranges
				for (i = server->ip_whitelist->ranges_number - 1; i >= 0; --i) {
					CHECK_REALM(server->ip_whitelist->rs[i].realm);
					if (ioa_addr_in_range(&(server->ip_whitelist->rs[i].enc), peer_addr))
						return 1;
				}
			}

			{
				ioa_lock_whitelist(server->e);

				const ip_range_list_t* wl = ioa_get_whitelist(server->e);
				if(wl) {
					// White listing of addr ranges
					for (i = wl->ranges_number - 1; i >= 0; --i) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -272,6 +272,8 @@
 		if(*(server->no_multicast_peers) && ioa_addr_is_multicast(peer_addr))
 			return 0;
 		if( !*(server->allow_loopback_peers) && ioa_addr_is_loopback(peer_addr))
+			return 0;
+		if (ioa_addr_is_zero(peer_addr))
 			return 0;
 
 		{
```
