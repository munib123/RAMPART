# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4211_1
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4211_1`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 1-25 of the vulnerable file.

import asyncio
import contextlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Union

import discord
from redbot.core import commands, i18n, checks, modlog
from redbot.core.commands import UserInputOptional
from redbot.core.utils import AsyncIter
from redbot.core.utils.chat_formatting import (
    pagify,
    humanize_number,
    bold,
    humanize_list,
    format_perms_list,
)
from redbot.core.utils.mod import get_audit_reason
from .abc import MixinMeta
from .converters import RawUserIds
from .utils import is_allowed_by_hierarchy

log = logging.getLogger("red.mod")
_ = i18n.Translator("Mod", __file__)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
 import contextlib
 import logging
 from datetime import datetime, timedelta, timezone
-from typing import Optional, Tuple, Union
+from typing import Dict, List, Optional, Tuple, Union
 
 import discord
 from redbot.core import commands, i18n, checks, modlog
@@ -440,28 +440,41 @@
             await show_results()
             return
 
+        # We need to check here, if any of the users isn't a member and if they are,
+        # we need to use our `ban_user()` method to do hierarchy checks.
+        members: Dict[int, discord.Member] = {}
+        to_query: List[int] = []
+
         for user_id in user_ids:
-            user = guild.get_member(user_id)
-            if user is not None:
-                if user_id in tempbans:
-                    # We need to check if a user is tempbanned here because otherwise they won't be processed later on.
-                    continue
+            member = guild.get_member(user_id)
+            if member is not None:
+                members[user_id] = member
+            elif not guild.chunked:
+                to_query.append(user_id)
+
+        # If guild isn't chunked, we might possibly be missing the member from cache,
+        # so we need to make sure that isn't the case by querying the user IDs for such guilds.
+        while to_query:
+            queried_members = await guild.query_members(user_ids=to_query[:100], limit=100)
+            members.update((member.id, member) for member in queried_members)
+            to_query = to_query[100:]
+
+        # Call `ban_user()` method for all users that turned out to be guild members.
+        for member in members:
+            try:
+                success, reason = await self.ban_user(
+                    user=member, ctx=ctx, days=days, reason=reason, create_modlog_case=True
+                )
+                if success:
+                    banned.append(user_id)
                 else:
-                    # Instead of replicating all that handling... gets attr from decorator
-                    try:
-                        success, reason = await self.ban_user(
-                            user=user, ctx=ctx, days=days, reason=reason, create_modlog_case=True
-                        )
-                        if success:
-                            banned.append(user_id)
-                        else:
-                            errors[user_id] = _("Failed to ban user {user_id}: {reason}").format(
-                                user_id=user_id, reason=reason
-                            )
-                    except Exception as e:
-                        errors[user_id] = _("Failed to ban user {user_id}: {reason}").format(
-                            user_id=user_id, reason=e
-                        )
+                    errors[user_id] = _("Failed to ban user {user_id}: {reason}").format(
+                        user_id=user_id, reason=reason
+                    )
+            except Exception as e:
+                errors[user_id] = _("Failed to ban user {user_id}: {reason}").format(
+                    user_id=user_id, reason=e
+                )
 
         user_ids = remove_processed(user_ids)
 
```
