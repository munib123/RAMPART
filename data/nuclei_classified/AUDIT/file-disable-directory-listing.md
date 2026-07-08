# Vulnerability: Disable Apache2 Directory Listing
**Classification:** AUDIT
**Source:** Nuclei Template (`file-disable-directory-listing.yaml`)

## Description
Directory listing should be disabled to prevent unauthorized users from browsing server directories.

## Secure Mitigation
Add 'Options -Indexes' in the Apache configuration file or .htaccess file.

