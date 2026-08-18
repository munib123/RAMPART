# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 3523_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3523_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 11-51 of the vulnerable file.

try:
    import lxml
    from lxml.etree import parse as parse_xml
    from lxml.etree import Element, tostring
except ImportError:
    lxml = None
try:
    import yaml
    from django.core.serializers import pyyaml
except ImportError:
    yaml = None
try:
    import biplist
except ImportError:
    biplist = None


class Serializer(object):
    """
    A swappable class for serialization.
    
    This handles most types of data as well as the following output formats::
    
        * json
        * jsonp
        * xml
        * yaml
        * html
        * plist (see http://explorapp.com/biplist/)
    
    It was designed to make changing behavior easy, either by overridding the
    various format methods (i.e. ``to_json``), by changing the
    ``formats/content_types`` options or by altering the other hook methods.
    """
    formats = ['json', 'jsonp', 'xml', 'yaml', 'html', 'plist']
    content_types = {
        'json': 'application/json',
        'jsonp': 'text/javascript',
        'xml': 'application/xml',
        'yaml': 'text/yaml',
        'html': 'text/html',
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,16 +28,16 @@
 class Serializer(object):
     """
     A swappable class for serialization.
-    
+
     This handles most types of data as well as the following output formats::
-    
+
         * json
         * jsonp
         * xml
         * yaml
         * html
         * plist (see http://explorapp.com/biplist/)
-    
+
     It was designed to make changing behavior easy, either by overridding the
     various format methods (i.e. ``to_json``), by changing the
     ``formats/content_types`` options or by altering the other hook methods.
@@ -51,30 +51,30 @@
         'html': 'text/html',
         'plist': 'application/x-plist',
     }
-    
+
     def __init__(self, formats=None, content_types=None, datetime_formatting=None):
         self.supported_formats = []
         self.datetime_formatting = getattr(settings, 'TASTYPIE_DATETIME_FORMATTING', 'iso-8601')
-        
+
         if formats is not None:
             self.formats = formats
-        
+
         if content_types is not None:
             self.content_types = content_types
-        
+
         if datetime_formatting is not None:
             self.datetime_formatting = datetime_formatting
-        
+
         for format in self.formats:
             try:
                 self.supported_formats.append(self.content_types[format])
             except KeyError:
                 raise ImproperlyConfigured("Content type for specified type '%s' not found. Please provide it at either the class level or via the arguments." % format)
-    
+
     def get_mime_for_format(self, format):
         """
         Given a format, attempts to determine the correct MIME type.
-        
+
         If not available on the current ``Serializer``, returns
         ``application/json`` by default.
         """
@@ -82,68 +82,68 @@
             return self.content_types[format]
         except KeyError:
             return 'application/json'
-    
+
     def format_datetime(self, data):
         """
         A hook to control how datetimes are formatted.
-        
+
         Can be overridden at the ``Serializer`` level (``datetime_formatting``)
         or globally (via ``settings.TASTYPIE_DATETIME_FORMATTING``).
-        
+
         Default is ``iso-8601``, which looks like "2010-12-16T03:02:14".
         """
         if self.datetime_formatting == 'rfc-2822':
             return format_datetime(data)
-        
+
         return data.isoformat()
-    
+
     def format_date(self, data):
         """
         A hook to control how dates are formatted.
-        
+
         Can be overridden at the ``Serializer`` level (``datetime_formatting``)
         or globally (via ``settings.TASTYPIE_DATETIME_FORMATTING``).
-        
+
         Default is ``iso-8601``, which looks like "2010-12-16".
         """
         if self.datetime_formatting == 'rfc-2822':
             return format_date(data)
-        
+
         return data.isoformat()
-    
+
     def format_time(self, data):
         """
         A hook to control how times are formatted.
-        
+
         Can be overridden at the ``Serializer`` level (``datetime_formatting``)
         or globally (via ``settings.TASTYPIE_DATETIME_FORMATTING``).
-        
+
         Default is ``iso-8601``, which looks like "03:02:14".
         """
         if self.datetime_formatting == 'rfc-2822':
             return format_time(data)
-        
+
         return data.isoformat()
-    
+
     def serialize(self, bundle, format='application/json', options={}):
         """
         Given some data and a format, calls the correct method to serialize
         the data and returns the result.
         """
         desired_format = None
-        
+
         for short_format, long_format in self.content_types.items():
             if format == long_format:
                 if hasattr(self, "to_%s" % short_format):
                     desired_format = short_format
                     break
-        
+
         if desired_format is None:
             raise UnsupportedFormat("The format indicated '%s' had no available serialization method. Please check your ``formats`` and ``content_types`` on your Serializer." % format)
-        
+
         serialized = getattr(self, "to_%s" % desired_format)(bundle, options)
         return serialized
-    
+
     def deserialize(self, content, format='application/json'):
         """
         Given some data and a format, calls the correct method to deserialize
@@ -158,10 +158,10 @@
                 if hasattr(self, "from_%s" % short_format):
                     desired_format = short_format
                     break
-        
+
         if desired_format is None:
             raise UnsupportedFormat("The format indicated '%s' had no available deserialization method. Please check your ``formats`` and ``content_types`` on your Serializer." % format)
-        
+
         deserialized = getattr(self, "from_%s" % desired_format)(content)
         return deserialized
 
@@ -169,7 +169,7 @@
         """
         For a piece of data, attempts to recognize it and provide a simplified
         form of something complex.
-        
+
         This brings complex Python data structures down to native types of the
         serialization format(s).
         """
@@ -293,7 +293,7 @@
                     return False
             else:
                 return None
-            
+
     def to_json(self, data, options=None):
         """
         Given some Python data, produces JSON output.
@@ -321,76 +321,76 @@
         Given some Python data, produces XML output.
         """
         options = options or {}
-        
+
         if lxml is None:
             raise ImproperlyConfigured("Usage of the XML aspects requires lxml.")
-        
+
         return tostring(self.to_etree(data, options), xml_declaration=True, encoding='utf-8')
-    
+
     def from_xml(self, content):
         """
         Given some XML data, returns a Python dictionary of the decoded data.
         """
         if lxml is None:
             raise ImproperlyConfigured("Usage of the XML aspects requires lxml.")
-        
+
         return self.from_etree(parse_xml(StringIO(content)).getroot())
-    
+
     def to_yaml(self, data, options=None):
         """
         Given some Python data, produces YAML output.
         """
         options = options or {}
-        
+
         if yaml is None:
             raise ImproperlyConfigured("Usage of the YAML aspects requires yaml.")
-        
+
         return yaml.dump(self.to_simple(data, options))
-    
+
     def from_yaml(self, content):
         """
         Given some YAML data, returns a Python dictionary of the decoded data.
         """
         if yaml is None:
             raise ImproperlyConfigured("Usage of the YAML aspects requires yaml.")
-        
-        return yaml.load(content)
-    
+
+        return yaml.safe_load(content)
+
     def to_plist(self, data, options=None):
         """
         Given some Python data, produces binary plist output.
         """
         options = options or {}
-        
+
         if biplist is None:
             raise ImproperlyConfigured("Usage of the plist aspects requires biplist.")
-        
+
         return biplist.writePlistToString(self.to_simple(data, options))
-    
+
     def from_plist(self, content):
         """
         Given some binary plist data, returns a Python dictionary of the decoded data.
         """
         if biplist is None:
             raise ImproperlyConfigured("Usage of the plist aspects requires biplist.")
-        
+
         return biplist.readPlistFromString(content)
-    
+
     def to_html(self, data, options=None):
         """
         Reserved for future usage.
-        
+
         The desire is to provide HTML output of a resource, making an API
         available to a browser. This is on the TODO list but not currently
         implemented.
         """
         options = options or {}
... (diff truncated)
```
