# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in python
**Pair ID:** 1574_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1574_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```python
Lines 1310-1350 of the vulnerable file.

        for plugname, plug in self.loaded_plugins:
            try:
                plug.postproc()
            except (OSError, IOError) as e:
                if e.errno in fatal_fs_errors:
                    self.ui_log.error("")
                    self.ui_log.error(" %s while post-processing plugin data"
                                      % e.strerror)
                    self.ui_log.error("")
                    self._exit(1)
            except:
                if self.raise_plugins:
                    raise

    def final_work(self):
        # this must come before archive creation to ensure that log
        # files are closed and cleaned up at exit.
        self._finish_logging()
        # package up the results for the support organization
        if not self.opts.build:
            if not self.opts.quiet:
                print(_("Creating compressed archive..."))
            # compression could fail for a number of reasons
            try:
                final_filename = self.archive.finalize(
                    self.opts.compression_type)
            except (OSError, IOError) as e:
                if e.errno in fatal_fs_errors:
                    self.ui_log.error("")
                    self.ui_log.error(" %s while finalizing archive"
                                      % e.strerror)
                    self.ui_log.error("")
                    self._exit(1)
            except:
                if self.opts.debug:
                    raise
                else:
                    return False
        else:
            final_filename = self.archive.get_archive_path()
        self.policy.display_results(final_filename, build=self.opts.build)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1327,6 +1327,7 @@
         self._finish_logging()
         # package up the results for the support organization
         if not self.opts.build:
+            old_umask = os.umask(0o077)
             if not self.opts.quiet:
                 print(_("Creating compressed archive..."))
             # compression could fail for a number of reasons
@@ -1345,6 +1346,8 @@
                     raise
                 else:
                     return False
+            finally:
+                os.umask(old_umask)
         else:
             final_filename = self.archive.get_archive_path()
         self.policy.display_results(final_filename, build=self.opts.build)
```
