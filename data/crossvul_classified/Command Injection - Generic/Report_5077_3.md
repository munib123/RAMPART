# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5077_3
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5077_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 503-543 of the vulnerable file.

        date_format = "%Y-%m-%d %H:%M:%S %Z"
        text += format_2_column_name_value(_("First Seen"),            self.first_seen_date.format(date_format))
        text += format_2_column_name_value(_("Last Seen"),             self.last_seen_date.format(date_format))
        text += format_2_column_name_value(_("Local ID"),              default_text(self.local_id))

        text += '\n' + _("Raw Audit Messages")
        avcbuf = ""
        for audit_record in self.audit_event.records:
            if audit_record.record_type == 'AVC':
                avcbuf += "\n" + audit_record.to_text() + "\n"
            else:
                avcbuf += "\ntype=%s msg=%s: " % (audit_record.record_type, audit_record.event_id)
                avcbuf += ' '.join(["%s=%s" % (k, audit_record.fields[k]) for k in audit_record.fields_ord]) +"\n"

        avcbuf += "\nHash: " + self.get_hash_str() 

        try:
            audit2allow = "/usr/bin/audit2allow"
            if os.path.exist(audit2allow):
                newbuf = "\n\naudit2allow"
                p =  Popen([audit2allow], shell=True,stdin=PIPE, stdout=PIPE)
                newbuf += p.communicate(avcbuf)[0]
                if os.path.exists("/var/lib/sepolgen/interface_info"):
                    newbuf += "\naudit2allow -R"
                    p =  Popen(["%s -R" % audit2allow ], shell=True,stdin=PIPE, stdout=PIPE)
                    newbuf += p.communicate(avcbuf)[0]
                avcbuf += newbuf
        except:
            pass

        text += avcbuf + '\n'

        return text

    def untranslated(self, func, *args, **kwargs):
        r'define.*untranslated\(.*\n'
        # Call the parameter function with the translations turned off
        # This function is not thread safe, since it manipulates globals

        global P_, _
        saved_translateP_ = P_
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -520,11 +520,11 @@
             audit2allow = "/usr/bin/audit2allow"
             if os.path.exist(audit2allow):
                 newbuf = "\n\naudit2allow"
-                p =  Popen([audit2allow], shell=True,stdin=PIPE, stdout=PIPE)
+                p =  Popen([audit2allow], stdin=PIPE, stdout=PIPE)
                 newbuf += p.communicate(avcbuf)[0]
                 if os.path.exists("/var/lib/sepolgen/interface_info"):
                     newbuf += "\naudit2allow -R"
-                    p =  Popen(["%s -R" % audit2allow ], shell=True,stdin=PIPE, stdout=PIPE)
+                    p =  Popen([audit2allow, "-R"], stdin=PIPE, stdout=PIPE)
                     newbuf += p.communicate(avcbuf)[0]
                 avcbuf += newbuf
         except:
```
