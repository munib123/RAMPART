# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in python
**Pair ID:** 4113_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4113_0`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```python
Lines 480-520 of the vulnerable file.

            "4. Copy your API key and run the command "
            "{command}\n\n"
            "Note: These tokens are sensitive and should only be used in a private channel\n"
            "or in DM with the bot.\n"
        ).format(
            command="`{}set api youtube api_key {}`".format(
                ctx.clean_prefix, _("<your_api_key_here>")
            )
        )

        await ctx.maybe_send_embed(message)

    @streamset.group()
    @commands.guild_only()
    async def message(self, ctx: commands.Context):
        """Manage custom message for stream alerts."""
        pass

    @message.command(name="mention")
    @commands.guild_only()
    async def with_mention(self, ctx: commands.Context, message: str = None):
        """Set stream alert message when mentions are enabled.

        Use `{mention}` in the message to insert the selected mentions.

        Use `{stream.name}` in the message to insert the channel or user name.

        For example: `[p]streamset message mention "{mention}, {stream.name} is live!"`
        """
        if message is not None:
            guild = ctx.guild
            await self.config.guild(guild).live_message_mention.set(message)
            await ctx.send(_("Stream alert message set!"))
        else:
            await ctx.send_help()

    @message.command(name="nomention")
    @commands.guild_only()
    async def without_mention(self, ctx: commands.Context, message: str = None):
        """Set stream alert message when mentions are disabled.

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -497,14 +497,13 @@
 
     @message.command(name="mention")
     @commands.guild_only()
-    async def with_mention(self, ctx: commands.Context, message: str = None):
+    async def with_mention(self, ctx: commands.Context, *, message: str = None):
         """Set stream alert message when mentions are enabled.
 
         Use `{mention}` in the message to insert the selected mentions.
-
-        Use `{stream.name}` in the message to insert the channel or user name.
-
-        For example: `[p]streamset message mention "{mention}, {stream.name} is live!"`
+        Use `{stream}` in the message to insert the channel or user name.
+
+        For example: `[p]streamset message mention "{mention}, {stream} is live!"`
         """
         if message is not None:
             guild = ctx.guild
@@ -515,12 +514,12 @@
 
     @message.command(name="nomention")
     @commands.guild_only()
-    async def without_mention(self, ctx: commands.Context, message: str = None):
+    async def without_mention(self, ctx: commands.Context, *, message: str = None):
         """Set stream alert message when mentions are disabled.
 
-        Use `{stream.name}` in the message to insert the channel or user name.
-
-        For example: `[p]streamset message nomention "{stream.name} is live!"`
+        Use `{stream}` in the message to insert the channel or user name.
+
+        For example: `[p]streamset message nomention "{stream} is live!"`
         """
         if message is not None:
             guild = ctx.guild
@@ -720,7 +719,10 @@
                                 channel.guild
                             ).live_message_mention()
                             if alert_msg:
-                                content = alert_msg.format(mention=mention_str, stream=stream)
+                                content = alert_msg  # Stop bad things from happening here...
+                                content = content.replace("{stream.name}", str(stream.name))  # Backwards compatability
+                                content = content.replace("{stream}", str(stream.name))
+                                content = content.replace("{mention}", mention_str)
                             else:
                                 content = _("{mention}, {stream} is live!").format(
                                     mention=mention_str,
@@ -733,7 +735,9 @@
                                 channel.guild
                             ).live_message_nomention()
                             if alert_msg:
-                                content = alert_msg.format(stream=stream)
+                                content = alert_msg  # Stop bad things from happening here...
+                                content = content.replace("{stream.name}", str(stream.name))  # Backwards compatability
+                                content = content.replace("{stream}", str(stream.name))
                             else:
                                 content = _("{stream} is live!").format(
                                     stream=escape(
```
