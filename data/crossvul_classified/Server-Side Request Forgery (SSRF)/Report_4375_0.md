# CrossVul Fix Pair: Unintended Proxy or Intermediary ('Confused Deputy') in c
**Pair ID:** 4375_0
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**CWE:** CWE-441
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4375_0`)

## Vulnerability Information & PoC

## Description
Unintended Proxy or Intermediary ('Confused Deputy') - If an attacker cannot directly contact a target, but the product has access to the target, then the attacker can send a request to the product and have it be forwarded to the target.

## Vulnerable Code
```c
Lines 466-506 of the vulnerable file.

	if(addr) {
		if(addr->ss.sa_family == AF_INET) {
			const uint8_t *u = ((const uint8_t*)&(addr->s4.sin_addr));
			return (u[0] > 223);
		} else if(addr->ss.sa_family == AF_INET6) {
			uint8_t u = ((const uint8_t*)&(addr->s6.sin6_addr))[0];
			return (u == 255);
		}
	}
	return 0;
}

int ioa_addr_is_loopback(ioa_addr *addr)
{
	if(addr) {
		if(addr->ss.sa_family == AF_INET) {
			const uint8_t *u = ((const uint8_t*)&(addr->s4.sin_addr));
			return (u[0] == 127);
		} else if(addr->ss.sa_family == AF_INET6) {
			const uint8_t *u = ((const uint8_t*)&(addr->s6.sin6_addr));
			if(u[7] == 1) {
				int i;
				for(i=0;i<7;++i) {
					if(u[i])
						return 0;
				}
				return 1;
			}
		}
	}
	return 0;
}

/////// Map "public" address to "private" address //////////////

// Must be called only in a single-threaded context,
// before the program starts spawning threads:

static ioa_addr **public_addrs = NULL;
static ioa_addr **private_addrs = NULL;
static size_t mcount = 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -483,14 +483,39 @@
 			return (u[0] == 127);
 		} else if(addr->ss.sa_family == AF_INET6) {
 			const uint8_t *u = ((const uint8_t*)&(addr->s6.sin6_addr));
-			if(u[7] == 1) {
+			if(u[15] == 1) {
 				int i;
-				for(i=0;i<7;++i) {
+				for(i=0;i<15;++i) {
 					if(u[i])
 						return 0;
 				}
 				return 1;
 			}
+		}
+	}
+	return 0;
+}
+
+/*
+To avoid a vulnerability this function checks whether the addr is in 0.0.0.0/8 or ::/128.
+Source from (INADDR_ANY) 0.0.0.0/32 and (in6addr_any) ::/128 routed to loopback on Linux systems for old BSD backward compatibility.
+https://github.com/torvalds/linux/blob/a2f5ea9e314ba6778f885c805c921e9362ec0420/net/ipv6/tcp_ipv6.c#L182
+To avoid any trouble we match the whole 0.0.0.0/8 that defined in RFC6890 as local network "this".
+*/
+int ioa_addr_is_zero(ioa_addr *addr)
+{
+	if(addr) {
+		if(addr->ss.sa_family == AF_INET) {
+			const uint8_t *u = ((const uint8_t*)&(addr->s4.sin_addr));
+			return (u[0] == 0);
+		} else if(addr->ss.sa_family == AF_INET6) {
+			const uint8_t *u = ((const uint8_t*)&(addr->s6.sin6_addr));
+			int i;
+			for(i=0;i<=15;++i) {
+				if(u[i])
+					return 0;
+			}
+			return 1;
 		}
 	}
 	return 0;
```
