# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_4
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_4`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 561-601 of the vulnerable file.

                        from_server=from_server,
                        ts_now_ms=time_added_ms,
                        ts_expires_ms=ts_valid_until_ms,
                        key_json_bytes=key_json_bytes,
                    )
                    for key_id in verify_keys
                ],
                consumeErrors=True,
            ).addErrback(unwrapFirstError)
        )

        return verify_keys


class PerspectivesKeyFetcher(BaseV2KeyFetcher):
    """KeyFetcher impl which fetches keys from the "perspectives" servers"""

    def __init__(self, hs):
        super().__init__(hs)
        self.clock = hs.get_clock()
        self.client = hs.get_http_client()
        self.key_servers = self.config.key_servers

    async def get_keys(self, keys_to_fetch):
        """see KeyFetcher.get_keys"""

        async def get_key(key_server):
            try:
                result = await self.get_server_verify_key_v2_indirect(
                    keys_to_fetch, key_server
                )
                return result
            except KeyLookupError as e:
                logger.warning(
                    "Key lookup failed from %r: %s", key_server.server_name, e
                )
            except Exception as e:
                logger.exception(
                    "Unable to get key from %r: %s %s",
                    key_server.server_name,
                    type(e).__name__,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -578,7 +578,7 @@
     def __init__(self, hs):
         super().__init__(hs)
         self.clock = hs.get_clock()
-        self.client = hs.get_http_client()
+        self.client = hs.get_federation_http_client()
         self.key_servers = self.config.key_servers
 
     async def get_keys(self, keys_to_fetch):
@@ -748,7 +748,7 @@
     def __init__(self, hs):
         super().__init__(hs)
         self.clock = hs.get_clock()
-        self.client = hs.get_http_client()
+        self.client = hs.get_federation_http_client()
 
     async def get_keys(self, keys_to_fetch):
         """
```
