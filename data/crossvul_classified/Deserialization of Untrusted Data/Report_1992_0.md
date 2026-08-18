# CrossVul Fix Pair: Deserialization of Untrusted Data in python
**Pair ID:** 1992_0
**Vulnerability Class:** Deserialization of Untrusted Data
**CWE:** CWE-502
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1992_0`)

## Vulnerability Information & PoC

## Description
Deserialization of Untrusted Data - It is often convenient to serialize objects for communication or to save them for later use.

## Vulnerable Code
```python
Lines 287-327 of the vulnerable file.

        logger.debug("yaml configuration parsed")
        return config

    def _recent_pyyaml(self):
        res = False
        try:
            version = yaml.__version__.split('.')
            if int(version[0]) >= 5:
                if int(version[1]) >= 1:
                    res = True
        except Exception as e:
            logger.debug("unable to parse PyYaml version: {}".format(e))
        return res

    def _load_yamlconfig(self, configfile):
        yamlconfig = None
        try:
            if self._recent_pyyaml():
                # https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
                # only for 5.1+
                yamlconfig = yaml.load(open(configfile), Loader=yaml.FullLoader)
            else:
                yamlconfig = yaml.load(open(configfile))
        except yaml.YAMLError as exc:
            logger.error("Error in configuration file {0}:".format(configfile))
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                raise PystemonConfigException("error position: (%s:%s)" % (mark.line + 1, mark.column + 1))
        for includes in yamlconfig.get("includes", []):
            try:
                logger.debug("loading include '{0}'".format(includes))
                yamlconfig.update(yaml.load(open(includes)))
            except Exception as e:
                raise PystemonConfigException("failed to load '{0}': {1}".format(includes, e))
        return yamlconfig


    def _load_user_agents_from_file(self, filename):
        user_agents_list = []
        logger.debug('Loading user-agent from file "{file}" ...'.format(file=filename))
        with open(filename) as f:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -304,9 +304,9 @@
             if self._recent_pyyaml():
                 # https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation
                 # only for 5.1+
-                yamlconfig = yaml.load(open(configfile), Loader=yaml.FullLoader)
+                yamlconfig = yaml.load(open(configfile), Loader=yaml.SafeLoader)
             else:
-                yamlconfig = yaml.load(open(configfile))
+                yamlconfig = yaml.safe_load(open(configfile))
         except yaml.YAMLError as exc:
             logger.error("Error in configuration file {0}:".format(configfile))
             if hasattr(exc, 'problem_mark'):
@@ -315,7 +315,7 @@
         for includes in yamlconfig.get("includes", []):
             try:
                 logger.debug("loading include '{0}'".format(includes))
-                yamlconfig.update(yaml.load(open(includes)))
+                yamlconfig.update(yaml.safe_load(open(includes)))
             except Exception as e:
                 raise PystemonConfigException("failed to load '{0}': {1}".format(includes, e))
         return yamlconfig
```
