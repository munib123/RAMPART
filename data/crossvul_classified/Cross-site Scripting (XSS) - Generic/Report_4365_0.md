# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in html
**Pair ID:** 4365_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4365_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```html
Lines 913-953 of the vulnerable file.


        // Change others to inactive, and the correct ones to active
        $('.prefix-option').removeClass('active')
        var index = $(this).index()
        $(".prefixdiv").each(function (someotherindexidontneed) {
            $(this).children().eq(index).addClass('active')
        })
    })
    function playGif(elm) {
        var img = $(elm)
        if (img.attr('data-is-animated') === "True") {
            img.attr("src", `${img.attr("data-src-url")}gif`)
        }
    }
    function stopGif(elm) {
        var img = $(elm)
        if (img.attr('data-is-animated') === "True") {
            img.attr("src", `${img.attr("data-src-url")}png`)
        }
    }
</script>

{% if data['status'] == 1 and data['data']['status'] == 1 %}

{% if 'aliascc' in data['data']['permslist'] %}
<script>
    /* ---------------------------------------------------------------------------------------------------------------------
                                                        Aliases group
       --------------------------------------------------------------------------------------------------------------------- */

    function safe(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Alias modal
    $(document).on('click', '.editaliasbutton', function () {
        var command = $(this).parent().parent().data("command")
        var textarea = $("#aliasModalCommand")
        textarea.text(command)
        textarea.height(textarea.prop('scrollHeight'))
        $("#aliasModal").modal('toggle')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -930,19 +930,19 @@
             img.attr("src", `${img.attr("data-src-url")}png`)
         }
     }
+
+    function safe(str) {
+        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
+    }
 </script>
 
 {% if data['status'] == 1 and data['data']['status'] == 1 %}
 
-{% if 'aliascc' in data['data']['permslist'] %}
+{% if 'aliascc' in data['data']['permslist'] and false%}
 <script>
     /* ---------------------------------------------------------------------------------------------------------------------
                                                         Aliases group
        --------------------------------------------------------------------------------------------------------------------- */
-
-    function safe(str) {
-        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
-    }
 
     // Alias modal
     $(document).on('click', '.editaliasbutton', function () {
@@ -1186,28 +1186,35 @@
             } else if (json.status === 1 && json.data.status === 0) {
                 $("#targetstatus").html(`{{ _('Failed to fetch targets') }}: ${json.data.message}`)
             } else {
+                let big_ol_dict = {}
                 select.html("")
 
                 var chopt = [`<optgroup label="{{ _('Channels') }}">`]
                 for (let [id, name] of json.data.CHANNELS) {
-                    chopt.push(`<option value=${id}>${name}</option>`)
+                    chopt.push(`<option value=${id} class="selectpicker-element-${id}">Loading...</option>`)
+                    big_ol_dict[id] = name
                 }
                 chopt.push("</optgroup>")
                 select.append(chopt.join(""))
 
                 var ropt = [`<optgroup label="{{ _('Roles') }}">`]
                 for (let [id, name] of json.data.ROLES) {
-                    ropt.push(`<option value=${id}>${name}</option>`)
+                    ropt.push(`<option value=${id} class="selectpicker-element-${id}">Loading...</option>`)
+                    big_ol_dict[id] = name
                 }
                 ropt.push("</optgroup>")
                 select.append(ropt.join(""))
 
                 var uopt = [`<optgroup label="{{ _('Users') }}">`]
                 for (let [id, name] of json.data.USERS) {
-                    uopt.push(`<option value=${id}>${name}</option>`)
+                    uopt.push(`<option value=${id} class="selectpicker-element-${id}">Loading...</option>`)
+                    big_ol_dict[id] = name
                 }
                 uopt.push("</optgroup>")
                 select.append(uopt.join(""))
+                for (let [id, name] of Object.entries(big_ol_dict)) {
+                    $(`.selectpicker-element-${id}`).text(name)
+                }
             }
             select.selectpicker({ title: "{{ _('Choose target') }}" })
             select.removeAttr("disabled")
@@ -1299,18 +1306,24 @@
                 $("#rulesdiv").html("")
                 var overall = ['<h3 style="margin-bottom: 10px">{{ _("Cog rules") }}</h3>']
                 var allcoglines = ["<ul>"]
+
+                let big_ol_dict_two = {}
+                let cog_counter = 0
+
                 for (let [cog, rules] of Object.entries(json.data.COG)) {
                     var coglines = []
                     for (let rule of rules) {
                         if (rule.type === "Default") {
                             coglines.unshift(`<li>{{ _('By default, users are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
                         } else if (rule.type === "Role") {
-                            coglines.push(`<li>{{ _('Users with the') }} <code>${rule.name}</code> {{ _('role') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
+                            coglines.push(`<li>{{ _('Users with the') }} <code id="cog-rules-${cog_counter}">Loading...</code> {{ _('role') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
                         } else if (rule.type === "Channel") {
-                            coglines.push(`<li>{{ _('Users in the') }} <code>${rule.name}</code> {{ _('channel') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
+                            coglines.push(`<li>{{ _('Users in the') }} <code id="cog-rules-${cog_counter}">Loading...</code> {{ _('channel') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
                         } else {
-                            coglines.push(`<li>{{ _('User') }} <code>${rule.name}</code> (${rule.id}) {{ _('is') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
+                            coglines.push(`<li>{{ _('User') }} <code id="cog-rules-${cog_counter}">Loading...</code> (${rule.id}) {{ _('is') }} ${rule.permission} {{ _('permission to use the') }} <code>${cog}</code> {{ _('cog') }}.</li>`)
                         }
+                        big_ol_dict_two[`cog-rules-${cog_counter}`] = rule.name
+                        cog_counter += 1
                     }
                     if (coglines) {
                         allcoglines = allcoglines.concat(coglines)
@@ -1324,18 +1337,23 @@
 
                 overall.push('<h3 style="margin-bottom: 10px">{{ _("Command rules") }}</h3>')
                 var allcmdlines = ["<ul>"]
+
+                let cmd_counter = 0
+
                 for (let [cmd, rules] of Object.entries(json.data.COMMAND)) {
                     var cmdlines = []
                     for (let rule of rules) {
                         if (rule.type === "Default") {
                             cmdlines.unshift(`<li>{{ _('By default, users are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
                         } else if (rule.type === "Role") {
-                            cmdlines.push(`<li>{{ _('Users with the') }} <code>${rule.name}</code> {{ _('role') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
+                            cmdlines.push(`<li>{{ _('Users with the') }} <code id="cmd-rules-${cmd_counter}">Loading...</code> {{ _('role') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
                         } else if (rule.type === "Channel") {
-                            cmdlines.push(`<li>{{ _('Users in the') }} <code>${rule.name}</code> {{ _('channel') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
+                            cmdlines.push(`<li>{{ _('Users in the') }} <code id="cmd-rules-${cmd_counter}">Loading...</code> {{ _('channel') }} (${rule.id}) {{ _('are') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
                         } else {
-                            cmdlines.push(`<li>{{ _('User') }} <code>${rule.name}</code> (${rule.id}) {{ _('is') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
+                            cmdlines.push(`<li>{{ _('User') }} <code id="cmd-rules-${cmd_counter}">Loading...</code> (${rule.id}) {{ _('is') }} ${rule.permission} {{ _('permission to use the') }} <code>${cmd}</code> {{ _('command') }}.</li>`)
                         }
+                        big_ol_dict_two[`cmd-rules-${cmd_counter}`] = rule.name
+                        cmd_counter += 1
... (diff truncated)
```
