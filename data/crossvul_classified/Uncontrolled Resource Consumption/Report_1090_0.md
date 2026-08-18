# CrossVul Fix Pair: Uncontrolled Resource Consumption in python
**Pair ID:** 1090_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1090_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```python
Lines 1467-1507 of the vulnerable file.

@one_time
def get_link_re() -> str:
    '''
    Very important--if you need to change this code to depend on
    any arguments, you must eliminate the "one_time" decorator
    and consider performance implications.  We only want to compute
    this value once.
    '''

    NOBRACKET = r'[^\]\[]*'
    BRK = (
        r'\[(' +
        (NOBRACKET + r'(\[')*6 +
        (NOBRACKET + r'\])*')*6 +
        NOBRACKET + r')\]'
    )
    NOIMG = r'(?<!\!)'

    # [text](url) or [text](<url>) or [text](url "title")
    LINK_RE = NOIMG + BRK + \
        r'''\(\s*(<.*?>|((?:(?:\(.*?\))|[^\(\)]))*?)\s*((['"])(.*?)\12\s*)?\)'''
    return normal_compile(LINK_RE)

def prepare_realm_pattern(source: str) -> str:
    """ Augment a realm filter so it only matches after start-of-string,
    whitespace, or opening delimiters, won't match if there are word
    characters directly after, and saves what was matched as "name". """
    return r"""(?<![^\s'"\(,:<])(?P<name>""" + source + r')(?!\w)'

# Given a regular expression pattern, linkifies groups that match it
# using the provided format string to construct the URL.
class RealmFilterPattern(markdown.inlinepatterns.Pattern):
    """ Applied a given realm filter to the input """

    def __init__(self, source_pattern: str,
                 format_string: str,
                 markdown_instance: Optional[markdown.Markdown]=None) -> None:
        self.pattern = prepare_realm_pattern(source_pattern)
        self.format_string = format_string
        markdown.inlinepatterns.Pattern.__init__(self, self.pattern, markdown_instance)

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1484,7 +1484,7 @@
 
     # [text](url) or [text](<url>) or [text](url "title")
     LINK_RE = NOIMG + BRK + \
-        r'''\(\s*(<.*?>|((?:(?:\(.*?\))|[^\(\)]))*?)\s*((['"])(.*?)\12\s*)?\)'''
+        r'''\(\s*(<(?:[^<>\\]|\\.)*>|(\([^()]*\)|[^()])*?)\s*(('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*)?\)'''
     return normal_compile(LINK_RE)
 
 def prepare_realm_pattern(source: str) -> str:
```
