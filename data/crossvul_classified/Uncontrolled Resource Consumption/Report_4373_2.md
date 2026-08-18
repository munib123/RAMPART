# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 4373_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4373_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 423-463 of the vulnerable file.

        try:
            code, response = await self.handler.on_incoming_transaction(
                origin, transaction_data
            )
        except Exception:
            logger.exception("on_incoming_transaction failed")
            raise

        return code, response


class FederationEventServlet(BaseFederationServlet):
    PATH = "/event/(?P<event_id>[^/]*)/?"

    # This is when someone asks for a data item for a given server data_id pair.
    async def on_GET(self, origin, content, query, event_id):
        return await self.handler.on_pdu_request(origin, event_id)


class FederationStateV1Servlet(BaseFederationServlet):
    PATH = "/state/(?P<context>[^/]*)/?"

    # This is when someone asks for all data for a given context.
    async def on_GET(self, origin, content, query, context):
        return await self.handler.on_context_state_request(
            origin,
            context,
            parse_string_from_args(query, "event_id", None, required=False),
        )


class FederationStateIdsServlet(BaseFederationServlet):
    PATH = "/state_ids/(?P<room_id>[^/]*)/?"

    async def on_GET(self, origin, content, query, room_id):
        return await self.handler.on_state_ids_request(
            origin,
            room_id,
            parse_string_from_args(query, "event_id", None, required=True),
        )

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -440,13 +440,13 @@
 
 
 class FederationStateV1Servlet(BaseFederationServlet):
-    PATH = "/state/(?P<context>[^/]*)/?"
-
-    # This is when someone asks for all data for a given context.
-    async def on_GET(self, origin, content, query, context):
-        return await self.handler.on_context_state_request(
+    PATH = "/state/(?P<room_id>[^/]*)/?"
+
+    # This is when someone asks for all data for a given room.
+    async def on_GET(self, origin, content, query, room_id):
+        return await self.handler.on_room_state_request(
             origin,
-            context,
+            room_id,
             parse_string_from_args(query, "event_id", None, required=False),
         )
 
@@ -463,16 +463,16 @@
 
 
 class FederationBackfillServlet(BaseFederationServlet):
-    PATH = "/backfill/(?P<context>[^/]*)/?"
-
-    async def on_GET(self, origin, content, query, context):
+    PATH = "/backfill/(?P<room_id>[^/]*)/?"
+
+    async def on_GET(self, origin, content, query, room_id):
         versions = [x.decode("ascii") for x in query[b"v"]]
         limit = parse_integer_from_args(query, "limit", None)
 
         if not limit:
             return 400, {"error": "Did not include limit param"}
 
-        return await self.handler.on_backfill_request(origin, context, versions, limit)
+        return await self.handler.on_backfill_request(origin, room_id, versions, limit)
 
 
 class FederationQueryServlet(BaseFederationServlet):
@@ -487,9 +487,9 @@
 
 
 class FederationMakeJoinServlet(BaseFederationServlet):
-    PATH = "/make_join/(?P<context>[^/]*)/(?P<user_id>[^/]*)"
-
-    async def on_GET(self, origin, _content, query, context, user_id):
+    PATH = "/make_join/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"
+
+    async def on_GET(self, origin, _content, query, room_id, user_id):
         """
         Args:
             origin (unicode): The authenticated server_name of the calling server
@@ -511,16 +511,16 @@
             supported_versions = ["1"]
 
         content = await self.handler.on_make_join_request(
-            origin, context, user_id, supported_versions=supported_versions
+            origin, room_id, user_id, supported_versions=supported_versions
         )
         return 200, content
 
 
 class FederationMakeLeaveServlet(BaseFederationServlet):
-    PATH = "/make_leave/(?P<context>[^/]*)/(?P<user_id>[^/]*)"
-
-    async def on_GET(self, origin, content, query, context, user_id):
-        content = await self.handler.on_make_leave_request(origin, context, user_id)
+    PATH = "/make_leave/(?P<room_id>[^/]*)/(?P<user_id>[^/]*)"
+
+    async def on_GET(self, origin, content, query, room_id, user_id):
+        content = await self.handler.on_make_leave_request(origin, room_id, user_id)
         return 200, content
 
 
@@ -528,7 +528,7 @@
     PATH = "/send_leave/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
 
     async def on_PUT(self, origin, content, query, room_id, event_id):
-        content = await self.handler.on_send_leave_request(origin, content, room_id)
+        content = await self.handler.on_send_leave_request(origin, content)
         return 200, (200, content)
 
 
@@ -538,43 +538,43 @@
     PREFIX = FEDERATION_V2_PREFIX
 
     async def on_PUT(self, origin, content, query, room_id, event_id):
-        content = await self.handler.on_send_leave_request(origin, content, room_id)
+        content = await self.handler.on_send_leave_request(origin, content)
         return 200, content
 
 
 class FederationEventAuthServlet(BaseFederationServlet):
-    PATH = "/event_auth/(?P<context>[^/]*)/(?P<event_id>[^/]*)"
-
-    async def on_GET(self, origin, content, query, context, event_id):
-        return await self.handler.on_event_auth(origin, context, event_id)
+    PATH = "/event_auth/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
+
+    async def on_GET(self, origin, content, query, room_id, event_id):
+        return await self.handler.on_event_auth(origin, room_id, event_id)
 
 
 class FederationV1SendJoinServlet(BaseFederationServlet):
-    PATH = "/send_join/(?P<context>[^/]*)/(?P<event_id>[^/]*)"
-
-    async def on_PUT(self, origin, content, query, context, event_id):
-        # TODO(paul): assert that context/event_id parsed from path actually
+    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
+
+    async def on_PUT(self, origin, content, query, room_id, event_id):
+        # TODO(paul): assert that room_id/event_id parsed from path actually
         #   match those given in content
-        content = await self.handler.on_send_join_request(origin, content, context)
+        content = await self.handler.on_send_join_request(origin, content)
         return 200, (200, content)
 
 
 class FederationV2SendJoinServlet(BaseFederationServlet):
-    PATH = "/send_join/(?P<context>[^/]*)/(?P<event_id>[^/]*)"
+    PATH = "/send_join/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
 
     PREFIX = FEDERATION_V2_PREFIX
 
-    async def on_PUT(self, origin, content, query, context, event_id):
-        # TODO(paul): assert that context/event_id parsed from path actually
+    async def on_PUT(self, origin, content, query, room_id, event_id):
+        # TODO(paul): assert that room_id/event_id parsed from path actually
         #   match those given in content
-        content = await self.handler.on_send_join_request(origin, content, context)
+        content = await self.handler.on_send_join_request(origin, content)
         return 200, content
 
 
 class FederationV1InviteServlet(BaseFederationServlet):
-    PATH = "/invite/(?P<context>[^/]*)/(?P<event_id>[^/]*)"
-
-    async def on_PUT(self, origin, content, query, context, event_id):
+    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
+
+    async def on_PUT(self, origin, content, query, room_id, event_id):
         # We don't get a room version, so we have to assume its EITHER v1 or
         # v2. This is "fine" as the only difference between V1 and V2 is the
         # state resolution algorithm, and we don't use that for processing
@@ -589,12 +589,12 @@
 
 
 class FederationV2InviteServlet(BaseFederationServlet):
-    PATH = "/invite/(?P<context>[^/]*)/(?P<event_id>[^/]*)"
+    PATH = "/invite/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
 
     PREFIX = FEDERATION_V2_PREFIX
 
-    async def on_PUT(self, origin, content, query, context, event_id):
-        # TODO(paul): assert that context/event_id parsed from path actually
+    async def on_PUT(self, origin, content, query, room_id, event_id):
+        # TODO(paul): assert that room_id/event_id parsed from path actually
         #   match those given in content
 
         room_version = content["room_version"]
@@ -616,9 +616,7 @@
     PATH = "/exchange_third_party_invite/(?P<room_id>[^/]*)"
 
     async def on_PUT(self, origin, content, query, room_id):
-        content = await self.handler.on_exchange_third_party_invite_request(
-            room_id, content
-        )
+        content = await self.handler.on_exchange_third_party_invite_request(content)
         return 200, content
 
 
```
