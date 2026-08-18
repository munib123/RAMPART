# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in javascript
**Pair ID:** 2470_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2470_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```javascript
Lines 1-24 of the vulnerable file.

require('dotenv').config()
const { exec } = require("child_process");
const { RichEmbed, Message } = require("discord.js");
module.exports = {
  name: "npm",
  args: true,
  usage: "<query>",
  aliases: ["pnpm"],
  description: "search a package on npm",
/**
  * @param { Message } message 
  * @param { Array<string> } args
 */
  execute: async (message, args) => {
    message.channel.startTyping();
    message.channel.send(
      `Searching \`${args
        .join(" ")
        .replace(/\n/g, " ")}\` on ${message.client.emojis.get(
         process.env.NPM_EMOJI_ID
        )}...`,
      { disableEveryone: true }
    );
    exec(
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,8 @@
 require('dotenv').config()
 const { exec } = require("child_process");
 const { RichEmbed, Message } = require("discord.js");
+const { escape } = require("querystring")
+const fetch = require("node-fetch")
 module.exports = {
   name: "npm",
   args: true,
@@ -21,11 +23,8 @@
         )}...`,
       { disableEveryone: true }
     );
-    exec(
-      `npm search ${args.join(" ").replace(/\n/g, " ")} -json -l`,
-      async (er, so, se) => {
-        if (so) {
-          const res = JSON.parse(so).map(
+    const response = await fetch("https://www.npmjs.com/search/suggestions?q=" + escape(args.join(" "))).then(r => r.json())
+       const res = response.map(
             (x, index) => `${index + 1}. ${x.name}`
           );
           message.channel
@@ -42,9 +41,9 @@
                 )
                 .on("collect", msg => {
                   const choice = parseInt(msg.content) - 1;
-                  if (!JSON.parse(so)[choice])
+                  if (!response[choice])
                     return message.reply("out of range.");
-                  const result = JSON.parse(so)[choice];
+                  const result = response[choice];
                   const embed = new RichEmbed()
                     .setColor("#ff0000")
                     .setTitle(result.name)
@@ -86,10 +85,6 @@
                   message.channel.send(embed);
                 });
             });
+            message.channel.stopTyping();
         }
-        if (se) await message.channel.send(se, { code: "xl", split: true });
-        message.channel.stopTyping();
-      }
-    );
   }
-};
```
