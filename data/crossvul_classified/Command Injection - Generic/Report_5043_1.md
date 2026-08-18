# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in python
**Pair ID:** 5043_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5043_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```python
Lines 443-483 of the vulnerable file.

        total_priority = 0
        if all:
            for p  in self.plugins:
                total_priority += p.priority
                plugins.append((p, ("allow_ypbind", "1")))
        else:
            for solution in self.plugin_list:
                for p  in self.plugins:
                    if solution.analysis_id == p.analysis_id:
                        total_priority += p.priority
                        plugins.append((p, tuple(solution.args)))
                        break

        plugins.sort(self.priority_sort)

        return total_priority, plugins

    def substitute(self, txt):
        return Template(txt).safe_substitute(self.template_substitutions)

    def format_details(self, replace=False):
        env = self.environment

        text = _("Additional Information:\n")
        text += format_2_column_name_value(_("Source Context"),        self.scontext.format())
        text += format_2_column_name_value(_("Target Context"),        self.tcontext.format())
        text += format_2_column_name_value(_("Target Objects"),        self.format_target_object())
        text += format_2_column_name_value(_("Source"),                default_text(self.source))
        text += format_2_column_name_value(_("Source Path"),           default_text(self.spath))
        text += format_2_column_name_value(_("Port"),                  default_text(self.port))
        if (replace):
            text += format_2_column_name_value(_("Host"),              "(removed)")
        else:
            text += format_2_column_name_value(_("Host"),                  default_text(self.sig.host))
        text += format_2_column_name_value(_("Source RPM Packages"),   default_text(self.format_rpm_list(self.src_rpm_list)))
        text += format_2_column_name_value(_("Target RPM Packages"),   default_text(self.format_rpm_list(self.tgt_rpm_list)))
        text += format_2_column_name_value(_("Policy RPM"),            default_text(env.policy_rpm))
        text += format_2_column_name_value(_("Selinux Enabled"),       default_text(env.selinux_enabled))
        text += format_2_column_name_value(_("Policy Type"),           default_text(env.policy_type))
        text += format_2_column_name_value(_("Enforcing Mode"),        default_text(env.enforce))
        if replace:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -460,6 +460,9 @@
     def substitute(self, txt):
         return Template(txt).safe_substitute(self.template_substitutions)
 
+    def substitute_array(self, args):
+        return [self.substitute(txt) for txt in args]
+
     def format_details(self, replace=False):
         env = self.environment
 
```
