# CrossVul Fix Pair: Deserialization of Untrusted Data in python
**Pair ID:** 4129_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4129_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

import itertools
import random
from typing import Union

import aiohttp
import discord
import inflection
from redbot.core import Config, checks, commands
from redbot.core.i18n import get_locale
from redbot.core.utils.chat_formatting import italics

from .helpers import *


class Act(commands.Cog):
    """
    This cog makes all commands, e.g. [p]fluff, into valid commands if
    you command the bot to act on a user, e.g. [p]fluff [botname].
    """

    __author__ = "Zephyrkul"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,15 +1,18 @@
-import itertools
+import functools
 import random
+import re
 from typing import Union
 
 import aiohttp
 import discord
 import inflection
-from redbot.core import Config, checks, commands
+from redbot.core import bot, Config, checks, commands
 from redbot.core.i18n import get_locale
 from redbot.core.utils.chat_formatting import italics
 
 from .helpers import *
+
+fmt_re = re.compile(r"{(?:0|user)(?:\.([^\{]+))?}")
 
 
 class Act(commands.Cog):
@@ -26,7 +29,7 @@
     async def red_delete_data_for_user(self, *, requester, user_id):
         pass  # No data to delete
 
-    def __init__(self, bot):
+    def __init__(self, bot: bot.Red):
         super().__init__()
         self.bot = bot
         self.config = Config.get_conf(self, identifier=2_113_674_295, force_registration=True)
@@ -34,7 +37,7 @@
         self.config.register_guild(custom={})
         self.try_after = None
 
-    async def initialize(self, bot):
+    async def initialize(self, bot: bot.Red):
         # temporary backwards compatibility
         key = await self.config.tenorkey()
         if not key:
@@ -42,8 +45,20 @@
         await bot.set_shared_api_tokens("tenor", api_key=key)
         await self.config.tenorkey.clear()
 
+    @staticmethod
+    def repl(target: discord.Member, match: re.Match):
+        if attr := match.group(1):
+            print(attr)
+            if attr.startswith("_") or "." in attr:
+                return str(target)
+            try:
+                return str(getattr(target, attr))
+            except AttributeError:
+                return str(target)
+        return str(target)
+
     @commands.command(hidden=True)
-    async def act(self, ctx, *, target: Union[discord.Member, str] = None):
+    async def act(self, ctx: commands.Context, *, target: Union[discord.Member, str] = None):
         """
         Acts on the specified user.
         """
@@ -87,7 +102,8 @@
             action.insert(iverb + 1, target.mention)
             message = italics(" ".join(action))
         else:
-            message = message.format(target, user=target)
+            assert isinstance(message, str)
+            message = fmt_re.sub(functools.partial(self.repl, target), message)
 
         # add reaction gif
         if self.try_after and ctx.message.created_at < self.try_after:
@@ -131,7 +147,7 @@
 
     @commands.group()
     @checks.is_owner()
-    async def actset(self, ctx):
+    async def actset(self, ctx: commands.Context):
         """
         Configure various settings for the act cog.
         """
@@ -139,7 +155,7 @@
     @actset.group(aliases=["custom"], invoke_without_command=True)
     @checks.admin_or_permissions(manage_guild=True)
     @commands.guild_only()
-    async def customize(self, ctx, command: str.lower, *, response: str = None):
+    async def customize(self, ctx: commands.Context, command: str.lower, *, response: str = None):
         """
         Customize the response to an action.
 
@@ -148,13 +164,19 @@
         """
         if not response:
             await self.config.guild(ctx.guild).clear_raw("custom", command)
+            await ctx.tick()
         else:
             await self.config.guild(ctx.guild).set_raw("custom", command, value=response)
-        await ctx.tick()
+            await ctx.send(
+                fmt_re.sub(functools.partial(self.repl, ctx.author), response),
+                allowed_mentions=discord.AllowedMentions(users=False),
+            )
 
     @customize.command(name="global")
     @checks.is_owner()
-    async def customize_global(self, ctx, command: str.lower, *, response: str = None):
+    async def customize_global(
+        self, ctx: commands.Context, command: str.lower, *, response: str = None
+    ):
         """
         Globally customize the response to an action.
 
@@ -170,7 +192,7 @@
     @actset.group(invoke_without_command=True)
     @checks.admin_or_permissions(manage_guild=True)
     @commands.guild_only()
-    async def ignore(self, ctx, command: str.lower):
+    async def ignore(self, ctx: commands.Context, command: str.lower):
         """
         Ignore or unignore the specified action.
 
@@ -189,7 +211,7 @@
 
     @ignore.command(name="global")
     @checks.is_owner()
-    async def ignore_global(self, ctx, command: str.lower):
+    async def ignore_global(self, ctx: commands.Context, command: str.lower):
         """
         Globally ignore or unignore the specified action.
 
@@ -205,7 +227,7 @@
 
     @actset.command()
     @checks.is_owner()
-    async def tenorkey(self, ctx):
+    async def tenorkey(self, ctx: commands.Context):
         """
         Sets a Tenor GIF API key to enable reaction gifs with act commands.
 
@@ -225,20 +247,14 @@
         await ctx.maybe_send_embed("\n".join(instructions))
 
     @commands.Cog.listener()
-    async def on_message(self, message):
-        if message.author.bot:
-            return
-
-        ctx = await self.bot.get_context(message)
-        if ctx.prefix is None or not ctx.invoked_with.replace("_", "").isalpha():
-            return
-
-        if ctx.valid and ctx.command.enabled:
-            try:
-                if await ctx.command.can_run(ctx):
-                    return
-            except commands.errors.CheckFailure:
-                return
-
-        ctx.command = self.act
-        await self.bot.invoke(ctx)
+    async def on_command_error(
+        self, ctx: commands.Context, error: commands.CommandError, unhandled_by_cog: bool = False
+    ):
+        if ctx.command == self.act:
+            return
+        if isinstance(error, commands.UserFeedbackCheckFailure):
+            # UserFeedbackCheckFailure inherits from CheckFailure
+            return
+        elif isinstance(error, (commands.CheckFailure, commands.CommandNotFound)):
+            ctx.command = self.act
+            await ctx.bot.invoke(ctx)
```
