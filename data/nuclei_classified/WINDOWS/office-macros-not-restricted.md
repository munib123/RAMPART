# Vulnerability: Microsoft Office Macros Not Restricted
**Classification:** WINDOWS
**Source:** Nuclei Template (`office-macros-not-restricted.yaml`)

## Description
Detected Microsoft Office macro restrictions were not configured, increasing the risk of macro-based malware delivery through Office documents.

## Secure Mitigation
Configure Group Policy to disable macros: User Configuration > Administrative Templates > Microsoft Office > Security > VBA Macro Notification Settings > Disable all without notification (VBAWarnings = 4).

