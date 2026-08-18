# CrossVul Fix Pair: URL Redirection to Untrusted Site ('Open Redirect') in python
**Pair ID:** 1915_2
**Vulnerability Class:** Open Redirect
**CWE:** CWE-601
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1915_2`)

## Vulnerability Information & PoC

## Description
URL Redirection to Untrusted Site ('Open Redirect') - An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL.

## Vulnerable Code
```python
Lines 249-289 of the vulnerable file.

            # Just interested in counts.
            result = await self.store.count_e2e_one_time_keys(user_id, device_id)
            return 200, {"one_time_key_counts": result}


class _NullContextManager(ContextManager[None]):
    """A context manager which does nothing."""

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


UPDATE_SYNCING_USERS_MS = 10 * 1000


class GenericWorkerPresence(BasePresenceHandler):
    def __init__(self, hs):
        super().__init__(hs)
        self.hs = hs
        self.is_mine_id = hs.is_mine_id
        self.http_client = hs.get_simple_http_client()

        self._presence_enabled = hs.config.use_presence

        # The number of ongoing syncs on this process, by user id.
        # Empty if _presence_enabled is false.
        self._user_to_num_current_syncs = {}  # type: Dict[str, int]

        self.notifier = hs.get_notifier()
        self.instance_id = hs.get_instance_id()

        # user_id -> last_sync_ms. Lists the users that have stopped syncing
        # but we haven't notified the master of that yet
        self.users_going_offline = {}

        self._bump_active_client = ReplicationBumpPresenceActiveTime.make_client(hs)
        self._set_state_client = ReplicationPresenceSetState.make_client(hs)

        self._send_stop_syncing_loop = self.clock.looping_call(
            self.send_stop_syncing, UPDATE_SYNCING_USERS_MS
        )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -266,7 +266,6 @@
         super().__init__(hs)
         self.hs = hs
         self.is_mine_id = hs.is_mine_id
-        self.http_client = hs.get_simple_http_client()
 
         self._presence_enabled = hs.config.use_presence
 
```
