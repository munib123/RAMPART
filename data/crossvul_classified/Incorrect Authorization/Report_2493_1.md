# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 2493_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2493_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 464-504 of the vulnerable file.

def json_stream_exists(request, user_profile, stream=REQ(),
                       autosubscribe=REQ(default=False)):
    # type: (HttpRequest, UserProfile, Text, bool) -> HttpResponse
    if not valid_stream_name(stream):
        return json_error(_("Invalid characters in stream name"))
    try:
        stream_id = Stream.objects.get(realm=user_profile.realm, name=stream).id
    except Stream.DoesNotExist:
        stream_id = None
    return stream_exists_backend(request, user_profile, stream_id, autosubscribe)

def stream_exists_backend(request, user_profile, stream_id, autosubscribe):
    # type: (HttpRequest, UserProfile, int, bool) -> HttpResponse
    try:
        stream = get_and_validate_stream_by_id(stream_id, user_profile.realm)
    except JsonableError:
        stream = None
    result = {"exists": bool(stream)}
    if stream is not None:
        recipient = get_recipient(Recipient.STREAM, stream.id)
        if autosubscribe:
            bulk_add_subscriptions([stream], [user_profile])
        result["subscribed"] = is_active_subscriber(
            user_profile=user_profile,
            recipient=recipient)

        return json_success(result) # results are ignored for HEAD requests
    return json_response(data=result, status=404)

def get_and_validate_stream_by_id(stream_id, realm):
    # type: (int, Realm) -> Stream
    try:
        stream = Stream.objects.get(pk=stream_id, realm_id=realm.id)
    except Stream.DoesNotExist:
        raise JsonableError(_("Invalid stream id"))
    return stream

@has_request_variables
def json_get_stream_id(request, user_profile, stream=REQ()):
    # type: (HttpRequest, UserProfile, Text) -> HttpResponse
    try:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -481,7 +481,7 @@
     result = {"exists": bool(stream)}
     if stream is not None:
         recipient = get_recipient(Recipient.STREAM, stream.id)
-        if autosubscribe:
+        if not stream.invite_only and autosubscribe:
             bulk_add_subscriptions([stream], [user_profile])
         result["subscribed"] = is_active_subscriber(
             user_profile=user_profile,
```
