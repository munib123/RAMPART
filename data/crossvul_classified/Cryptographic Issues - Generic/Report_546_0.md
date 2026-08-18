# CrossVul Fix Pair: Cryptographic Issues in python
**Pair ID:** 546_0
**Vulnerability Class:** Cryptographic Issues - Generic
**CWE:** CWE-310
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `546_0`)

## Vulnerability Information & PoC

## Description
Cryptographic Issues

## Vulnerable Code
```python
Lines 793-833 of the vulnerable file.

        #
        if not selectors and self.version_tuple() < (2, 1):
            selectors = [".", "a", "e", "i", "p", "t", "k"]

        list_keys = ["--fingerprint"]
        if selectors:
            for sel in selectors:
                list_keys += ["--list-secret-keys", sel]
        else:
            list_keys += ["--list-secret-keys"]

        self.event.running_gpg(_('Fetching GnuPG secret key list (selectors=%s)'
                                 ) % ', '.join(selectors or ['None']))
        retvals = self.run(list_keys)
        secret_keys = self.parse_keylist(retvals[1]["stdout"])

        # Another unfortunate thing GPG does, is it hides the disabled
        # state when listing secret keys; it seems internally only the
        # public key is disabled. This makes it hard for us to reason about
        # which keys can actually be used, so we compensate...
        list_keys = ["--fingerprint"]
        for fprint in set(secret_keys):
            list_keys += ["--list-keys", fprint]
        retvals = self.run(list_keys)
        public_keys = self.parse_keylist(retvals[1]["stdout"])
        for fprint, info in public_keys.iteritems():
            if fprint in set(secret_keys):
                for k in ("disabled", "revoked"):  # FIXME: Copy more?
                    secret_keys[fprint][k] = info[k]

        return secret_keys

    def import_keys(self, key_data=None):
        """
        Imports gpg keys from a file object or string.
        >>> key_data = open("testing/pub.key").read()
        >>> g = GnuPG(None)
        >>> g.import_keys(key_data)
        {'failed': [], 'updated': [{'details_text': 'unchanged', 'details': 0, 'fingerprint': '08A650B8E2CBC1B02297915DC65626EED13C70DA'}], 'imported': [], 'results': {'sec_dups': 0, 'unchanged': 1, 'num_uids': 0, 'skipped_new_keys': 0, 'no_userids': 0, 'num_signatures': 0, 'num_revoked': 0, 'sec_imported': 0, 'sec_read': 0, 'not_imported': 0, 'count': 1, 'imported_rsa': 0, 'imported': 0, 'num_subkeys': 0}}
        """
        self.event.running_gpg(_('Importing key to GnuPG key chain'))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -810,6 +810,9 @@
         # state when listing secret keys; it seems internally only the
         # public key is disabled. This makes it hard for us to reason about
         # which keys can actually be used, so we compensate...
+        # *** FIXME JackDca 2018-09-21 - Above behaviour not seen in 2.1.18 if
+        # --with-colons is used (but true for human-readable output) so this
+        # code could be deleted.
         list_keys = ["--fingerprint"]
         for fprint in set(secret_keys):
             list_keys += ["--list-keys", fprint]
```
