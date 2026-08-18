# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_5
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_5`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 828-868 of the vulnerable file.

    return False


def _acl_entry_matches(server_name: str, acl_entry: Any) -> bool:
    if not isinstance(acl_entry, str):
        logger.warning(
            "Ignoring non-str ACL entry '%s' (is %s)", acl_entry, type(acl_entry)
        )
        return False
    regex = glob_to_regex(acl_entry)
    return bool(regex.match(server_name))


class FederationHandlerRegistry:
    """Allows classes to register themselves as handlers for a given EDU or
    query type for incoming federation traffic.
    """

    def __init__(self, hs: "HomeServer"):
        self.config = hs.config
        self.http_client = hs.get_simple_http_client()
        self.clock = hs.get_clock()
        self._instance_name = hs.get_instance_name()

        # These are safe to load in monolith mode, but will explode if we try
        # and use them. However we have guards before we use them to ensure that
        # we don't route to ourselves, and in monolith mode that will always be
        # the case.
        self._get_query_client = ReplicationGetQueryRestServlet.make_client(hs)
        self._send_edu = ReplicationFederationSendEduRestServlet.make_client(hs)

        self.edu_handlers = (
            {}
        )  # type: Dict[str, Callable[[str, dict], Awaitable[None]]]
        self.query_handlers = {}  # type: Dict[str, Callable[[dict], Awaitable[None]]]

        # Map from type to instance name that we should route EDU handling to.
        self._edu_type_to_instance = {}  # type: Dict[str, str]

    def register_edu_handler(
        self, edu_type: str, handler: Callable[[str, JsonDict], Awaitable[None]]
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -845,7 +845,6 @@
 
     def __init__(self, hs: "HomeServer"):
         self.config = hs.config
-        self.http_client = hs.get_simple_http_client()
         self.clock = hs.get_clock()
         self._instance_name = hs.get_instance_name()
 
```
