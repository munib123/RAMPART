# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 2141_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2141_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 63-103 of the vulnerable file.

    if some extensions are set via jinja_extensions in ansible.cfg, we try
    to load them with the jinja environment
    '''
    jinja_exts = []
    if C.DEFAULT_JINJA2_EXTENSIONS:
        '''
        Let's make sure the configuration directive doesn't contain spaces
        and split extensions in an array
        '''
        jinja_exts = C.DEFAULT_JINJA2_EXTENSIONS.replace(" ", "").split(',')

    return jinja_exts

class Flags:
    LEGACY_TEMPLATE_WARNING = False

# TODO: refactor this file

FILTER_PLUGINS = None
_LISTRE = re.compile(r"(\w+)\[(\d+)\]")
JINJA2_OVERRIDE='#jinja2:'

def lookup(name, *args, **kwargs):
    from ansible import utils
    instance = utils.plugins.lookup_loader.get(name.lower(), basedir=kwargs.get('basedir',None))
    vars = kwargs.get('vars', None)

    if instance is not None:
        # safely catch run failures per #5059
        try:
            ran = instance.run(*args, inject=vars, **kwargs)
        except errors.AnsibleError:
            # Plugin raised this on purpose
            raise
        except Exception, e:
            ran = None
        if ran:
            ran = ",".join(ran)
        return ran
    else:
        raise errors.AnsibleError("lookup plugin (%s) not found" % name)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,7 +80,6 @@
 
 FILTER_PLUGINS = None
 _LISTRE = re.compile(r"(\w+)\[(\d+)\]")
-JINJA2_OVERRIDE='#jinja2:'
 
 def lookup(name, *args, **kwargs):
     from ansible import utils
@@ -230,16 +229,6 @@
         raise errors.AnsibleError("unable to process as utf-8: %s" % realpath)
     except:
         raise errors.AnsibleError("unable to read %s" % realpath)
-
-
-    # Get jinja env overrides from template
-    if data.startswith(JINJA2_OVERRIDE):
-        eol = data.find('\n')
-        line = data[len(JINJA2_OVERRIDE):eol]
-        data = data[eol+1:]
-        for pair in line.split(','):
-            (key,val) = pair.split(':')
-            setattr(environment,key.strip(),ast.literal_eval(val.strip()))
 
     environment.template_class = J2Template
     try:
```
