# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in python
**Pair ID:** 1622_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1622_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```python
Lines 45-85 of the vulnerable file.

            msg = args and msg % args or msg
            if kw.get('newline', True):
                print(msg)
            else:
                print(msg, end=' ')

    def do_serve(self, args):
        """Start Attic in server mode. This command is usually not used manually.
        """
        return RepositoryServer(restrict_to_paths=args.restrict_to_paths).serve()

    def do_init(self, args):
        """Initialize an empty repository"""
        print('Initializing repository at "%s"' % args.repository.orig)
        repository = self.open_repository(args.repository, create=True, exclusive=True)
        key = key_creator(repository, args)
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        repository.commit()
        return self.exit_code

    def do_check(self, args):
        """Check repository consistency"""
        repository = self.open_repository(args.repository, exclusive=args.repair)
        if args.repair:
            while not os.environ.get('ATTIC_CHECK_I_KNOW_WHAT_I_AM_DOING'):
                self.print_error("""Warning: 'check --repair' is an experimental feature that might result
in data loss.

Type "Yes I am sure" if you understand this and want to continue.\n""")
                if input('Do you want to continue? ') == 'Yes I am sure':
                    break
        if not args.archives_only:
            print('Starting repository check...')
            if repository.check(repair=args.repair):
                print('Repository check complete, no problems found.')
            else:
                return 1
        if not args.repo_only and not ArchiveChecker().check(repository, repair=args.repair):
                return 1
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -62,6 +62,7 @@
         manifest.key = key
         manifest.write()
         repository.commit()
+        Cache(repository, key, manifest, warn_if_unencrypted=False)
         return self.exit_code
 
     def do_check(self, args):
```
