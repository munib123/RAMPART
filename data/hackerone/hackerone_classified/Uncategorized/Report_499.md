# HackerOne Report: Ruby: Heap Overflow in Floating Point Parsing
**Report ID:** 499
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Any time a string is converted to a floating point value, a specially crafted string can cause a heap overflow. This can lead to a denial of service attack via segmentation faults and possibly arbitrary code execution. Any program that converts input of unknown origin to floating point values (especially common when accepting JSON) are vulnerable.

Vulnerable code looks something like this:

`untrusted_data.to_f`

But any code that produces floating point values from external data is vulnerable, such as this:

`JSON.parse untrusted_data`

Note that this bug is similar to CVE-2009-0689.

All users running an affected release should upgrade to the FIXED versions of Ruby.

#Affected versions
- All Ruby 1.8 versions
- All Ruby 1.9 versions prior to Ruby 1.9.3 patchlevel 484
- All Ruby 2.0 versions prior to Ruby 2.0.0 patchlevel 353
- All Ruby 2.1 versions prior to Ruby 2.1.0 preview2
- prior to trunk revision 43780

#Solutions
All users are recommended to upgrade to Ruby 1.9.3 patchlevel 484, Ruby 2.0.0 patchlevel 353 or Ruby 2.1.0 preview2.

Please note that Ruby 1.8 series or any earlier releases are already obsoleted. There is no plan to release new FIXED versions for them. Users of such versions are advised to upgrade as soon as possible as we cannot guarantee the continued availability of security fixes for unsupported releases.


## Discussion & Remediation Timeline
