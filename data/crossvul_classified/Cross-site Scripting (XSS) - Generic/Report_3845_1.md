# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3845_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3845_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 177-217 of the vulnerable file.

                if (alarm.params && alarm.params.notify) {
                    if (alarm.params.notify.ajax) {
                        message = new Element('a')
                            .insert(message)
                            .observe('click', function(e) {
                                this.Growler.ungrowl(e.findElement('div'));
                                this.go(alarm.params.notify.ajax);
                            }.bindAsEventListener(this));
                    } else if (alarm.params.notify.url) {
                        message = new Element('a', { href: alarm.params.notify.url })
                            .insert(message);
                    }
                    if (alarm.params.notify.sound) {
                        Sound.play(alarm.params.notify.sound);
                    }
                }
                message = new Element('div')
                    .insert(message);
                if (alarm.params && alarm.params.notify &&
                    alarm.params.notify.subtitle) {
                    message.insert(new Element('br')).insert(alarm.params.notify.subtitle);
                }
                if (alarm.user) {
                    var select = '<select>';
                    $H(Kronolith.conf.snooze).each(function(snooze) {
                        select += '<option value="' + snooze.key + '">' + snooze.value + '</option>';
                    });
                    select += '</select>';
                    message.insert('<br /><br />' + Kronolith.text.snooze.interpolate({ time: select, dismiss_start: '<input type="button" value="', dismiss_end: '" class="button ko" />' }));
                }
                var growl = this.Growler.growl(message, {
                    className: 'horde-alarm',
                    life: 8,
                    log: false,
                    sticky: true
                });
                growl.store('alarm', alarm.id);

                document.observe('Growler:destroyed', function(e) {
                    var id = e.element().retrieve('alarm');
                    if (id) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -194,7 +194,7 @@
                     .insert(message);
                 if (alarm.params && alarm.params.notify &&
                     alarm.params.notify.subtitle) {
-                    message.insert(new Element('br')).insert(alarm.params.notify.subtitle);
+                    message.insert(new Element('br')).insert(alarm.params.notify.subtitle.escapeHTML());
                 }
                 if (alarm.user) {
                     var select = '<select>';
@@ -811,7 +811,7 @@
             return this.setTitle(Kronolith.text.agenda + ' ' + dates[0].toString(Kronolith.conf.date_format) + ' - ' + dates[1].toString(Kronolith.conf.date_format));
 
         case 'search':
-            return this.setTitle(Kronolith.text.searching.interpolate({ term: data }));
+            return this.setTitle(Kronolith.text.searching.interpolate({ term: data })).escapeHTML();
         }
     },
 
@@ -2494,7 +2494,7 @@
 
         if (!Object.isUndefined(task.value.sd)) {
             col.insert(new Element('span', { className: 'kronolithSeparator' }).update(' &middot; '));
-            col.insert(new Element('span', { className: 'kronolithInfo' }).update(task.value.sd));
+            col.insert(new Element('span', { className: 'kronolithInfo' }).update(task.value.sd.escapeHTML()));
         }
 
         row.insert(col.show());
@@ -2988,7 +2988,7 @@
                     $('kronolithCalendarholidayDriver').insert(
                         new Element('option', { value: calendar.name })
                             .setStyle({ color: calendar.fg, backgroundColor: calendar.bg })
-                            .insert(calendar.name)
+                            .insert(calendar.name.escapeHTML())
                     );
                 });
                 break;
@@ -5329,7 +5329,7 @@
         $('kronolithEventId').setValue(ev.id);
         $('kronolithEventCalendar').setValue(ev.ty + '|' + ev.c);
         $('kronolithEventTarget').setValue(ev.ty + '|' + ev.c);
-        $('kronolithEventTargetRO').update(Kronolith.conf.calendars[ev.ty][ev.c].name);
+        $('kronolithEventTargetRO').update(Kronolith.conf.calendars[ev.ty][ev.c].name.escapeHTML());
         $('kronolithEventTitle').setValue(ev.t);
         $('kronolithEventLocation').setValue(ev.l);
         if (ev.l && Kronolith.conf.maps.driver) {
```
