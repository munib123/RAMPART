# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2944_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2944_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 3305-3345 of the vulnerable file.

                form.down('.kronolithFormActions .kronolithSeparator').show();
                if ($('kronolithCalendar' + type + 'LinkPerms')) {
                    $('kronolithCalendar' + type + 'LinkPerms').up('span').hide();
                }
            } else {
                form.down('.kronolithFormActions .kronolithSeparator').hide();
            }
        }
    },

    /**
     * Updates the select list in the resourcegroup calendar dialog.
     */
    updateResourcegroupSelect: function()
    {
        if (!Kronolith.conf.calendars.resource) {
            return;
        }
        $('kronolithCalendarresourcegroupmembers').update();
        $H(Kronolith.conf.calendars.resource).each(function(r) {
            var o = new Element('option', { value: r.value.id }).update(r.value.name);
            $('kronolithCalendarresourcegroupmembers').insert(o);
        });
    },

    /**
     * Handles clicks on the radio boxes of the basic permissions screen.
     *
     * @param string type  The calendar type, 'internal' or 'taskslists'.
     * @param string perm  The permission to activate, 'None', 'All', or
     *                     'Group'.
     */
    permsClickHandler: function(type, perm)
    {
        $('kronolithC' + type + 'PAdvanced')
            .select('input[type=checkbox]')
            .invoke('setValue', 0);
        $('kronolithC' + type + 'PAdvanced').select('tr').findAll(function(tr) {
            return tr.retrieve('remove');
        }).invoke('remove');

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3322,7 +3322,7 @@
         }
         $('kronolithCalendarresourcegroupmembers').update();
         $H(Kronolith.conf.calendars.resource).each(function(r) {
-            var o = new Element('option', { value: r.value.id }).update(r.value.name);
+            var o = new Element('option', { value: r.value.id }).update(r.value.name.escapeHTML());
             $('kronolithCalendarresourcegroupmembers').insert(o);
         });
     },
```
