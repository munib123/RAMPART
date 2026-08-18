# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2823_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2823_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 1530-1570 of the vulnerable file.

            Ext.each(busyAttendee, function(busyAttender) {
                // TODO refactore name handling of attendee
                //      -> attender model needs knowlege of how to get names!
                //var attenderName = a.getName();
                var attenderName = Tine.Calendar.AttendeeGridPanel.prototype.renderAttenderName.call(Tine.Calendar.AttendeeGridPanel.prototype, busyAttender.get('user_id'), false, busyAttender);
                busyAttendeeHTML += '<div class="cal-conflict-attendername">' + attenderName + '</div>';
                
                var eventInfos = [];
                Ext.each(conflictEvents[busyAttender.id], function(fbInfo) {
                    var format = 'H:i';
                    var eventInfo;
                    var dateFormat = Ext.form.DateField.prototype.format;
                    if (event.get('dtstart').format(dateFormat) != event.get('dtend').format(dateFormat) ||
                        Date.parseDate(fbInfo.dtstart, Date.patterns.ISO8601Long).format(dateFormat) != Date.parseDate(fbInfo.dtend, Date.patterns.ISO8601Long).format(dateFormat))
                    {
                        eventInfo = Date.parseDate(fbInfo.dtstart, Date.patterns.ISO8601Long).format(dateFormat + ' ' + format) + ' - ' + Date.parseDate(fbInfo.dtend, Date.patterns.ISO8601Long).format(dateFormat + ' ' + format);
                    } else {
                        eventInfo = Date.parseDate(fbInfo.dtstart, Date.patterns.ISO8601Long).format(dateFormat + ' ' + format) + ' - ' + Date.parseDate(fbInfo.dtend, Date.patterns.ISO8601Long).format(format);
                    }
                    if (fbInfo.event && fbInfo.event.summary) {
                        eventInfo += ' : ' + fbInfo.event.summary;
                    }
                    if (fbInfo.type == 'BUSY_UNAVAILABLE') {
                        denyIgnore = true;
                        eventInfo += '<span class="cal-conflict-eventinfos-unavailable">' + this.app.i18n._('Unavailable') + '</span>';
                    }
                    eventInfos.push(eventInfo);
                }, this);
                busyAttendeeHTML += '<div class="cal-conflict-eventinfos">' + eventInfos.join(', <br />') + '</div>';
                
            }, this);
            
            this.conflictConfirmWin = Tine.widgets.dialog.MultiOptionsDialog.openWindow({
                modal: true,
                allowCancel: false,
                height: 180 + 15*error.freebusyinfo.length,
                title: this.app.i18n._('Scheduling Conflict'),
                questionText: '<div class = "cal-conflict-heading">' +
                                   this.app.i18n._('The following attendee are busy at the requested time:') + 
                               '</div>' +
                               busyAttendeeHTML,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1547,7 +1547,7 @@
                         eventInfo = Date.parseDate(fbInfo.dtstart, Date.patterns.ISO8601Long).format(dateFormat + ' ' + format) + ' - ' + Date.parseDate(fbInfo.dtend, Date.patterns.ISO8601Long).format(format);
                     }
                     if (fbInfo.event && fbInfo.event.summary) {
-                        eventInfo += ' : ' + fbInfo.event.summary;
+                        eventInfo += ' : ' + Ext.util.Format.htmlEncode(fbInfo.event.summary);
                     }
                     if (fbInfo.type == 'BUSY_UNAVAILABLE') {
                         denyIgnore = true;
```
