# CrossVul Fix Pair: Improper Input Validation in csharp
**Pair ID:** 1278_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** csharp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1278_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```csharp
Lines 41-66 of the vulnerable file.


                string organisationName = this.OrganisationName;
                if (string.IsNullOrEmpty(organisationName))
                {
                    organisationName = "an organisation";
                }

                if (IsOrganisationAdmin)
                {
                    return string.Format("You have been invited to become an administrator of {0} by {1}", organisationName, inviteeSummary);
                }
                else
                {
                    return string.Format("You have been invited to join {0} by {1}", organisationName, inviteeSummary);
                }
            }
        }

        public int OrganisationId { get; set; }

        public bool IsOrganisationAdmin { get; set; }

        public List<string> DatabasesMerged { get; set; }
        public List<string> DatabasesLost { get; set; }
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -58,6 +58,8 @@
 
         public int OrganisationId { get; set; }
 
+        public int OrganisationInviteId { get; set; }
+
         public bool IsOrganisationAdmin { get; set; }
 
         public List<string> DatabasesMerged { get; set; }
```
