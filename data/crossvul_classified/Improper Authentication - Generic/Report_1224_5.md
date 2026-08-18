# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 1224_5
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1224_5`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 311-351 of the vulnerable file.

    if len(request.FILES) == 0:
        avatar_source = UserProfile.AVATAR_FROM_GRAVATAR
    elif len(request.FILES) != 1:
        return json_error(_("You may only upload one file at a time"))
    else:
        avatar_source = UserProfile.AVATAR_FROM_USER

    default_sending_stream = None
    if default_sending_stream_name is not None:
        (default_sending_stream, ignored_rec, ignored_sub) = access_stream_by_name(
            user_profile, default_sending_stream_name)

    default_events_register_stream = None
    if default_events_register_stream_name is not None:
        (default_events_register_stream, ignored_rec, ignored_sub) = access_stream_by_name(
            user_profile, default_events_register_stream_name)

    if bot_type in (UserProfile.INCOMING_WEBHOOK_BOT, UserProfile.EMBEDDED_BOT) and service_name:
        check_valid_bot_config(bot_type, service_name, config_data)

    bot_profile = do_create_user(email=email, password='',
                                 realm=user_profile.realm, full_name=full_name,
                                 short_name=short_name,
                                 bot_type=bot_type,
                                 bot_owner=user_profile,
                                 avatar_source=avatar_source,
                                 default_sending_stream=default_sending_stream,
                                 default_events_register_stream=default_events_register_stream,
                                 default_all_public_streams=default_all_public_streams)
    if len(request.FILES) == 1:
        user_file = list(request.FILES.values())[0]
        upload_avatar_image(user_file, user_profile, bot_profile)

    if bot_type in (UserProfile.OUTGOING_WEBHOOK_BOT, UserProfile.EMBEDDED_BOT):
        assert(isinstance(service_name, str))
        add_service(name=service_name,
                    user_profile=bot_profile,
                    base_url=payload_url,
                    interface=interface_type,
                    token=generate_api_key())

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,7 +328,7 @@
     if bot_type in (UserProfile.INCOMING_WEBHOOK_BOT, UserProfile.EMBEDDED_BOT) and service_name:
         check_valid_bot_config(bot_type, service_name, config_data)
 
-    bot_profile = do_create_user(email=email, password='',
+    bot_profile = do_create_user(email=email, password=None,
                                  realm=user_profile.realm, full_name=full_name,
                                  short_name=short_name,
                                  bot_type=bot_type,
```
