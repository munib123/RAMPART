# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in python
**Pair ID:** 2836_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2836_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```python
Lines 846-886 of the vulnerable file.

def main():
    global logger
    result = 0

    parser = argparse.ArgumentParser(description='Keycloak REST client',
                    prog=prog_name,
                    epilog=verbose_help.format(prog_name=prog_name),
                    formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='be chatty')

    parser.add_argument('-d', '--debug', action='store_true',
                        help='turn on debug info')

    parser.add_argument('--show-traceback', action='store_true',
                        help='exceptions print traceback in addition to '
                             'error message')

    parser.add_argument('--log-file',
                        default='/tmp/{prog_name}.log'.format(
                            prog_name=prog_name),
                        help='log file pathname')

    parser.add_argument('--permit-insecure-transport',  action='store_true',
                        help='Normally secure transport such as TLS '
                        'is required, defeat this check')

    parser.add_argument('--tls-verify', action=TlsVerifyAction,
                        default=True,
                        help='TLS certificate verification for requests to'
                        ' the server. May be one of case insenstive '
                        '[true, yes, on] to enable,'
                        '[false, no, off] to disable.'
                        'Or the pathname to a OpenSSL CA bundle to use.'
                        ' Default is True.')

    group = parser.add_argument_group('Server')

    group.add_argument('-s', '--server',
                       required=True,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -863,7 +863,7 @@
                              'error message')
 
     parser.add_argument('--log-file',
-                        default='/tmp/{prog_name}.log'.format(
+                        default='{prog_name}.log'.format(
                             prog_name=prog_name),
                         help='log file pathname')
 
```
