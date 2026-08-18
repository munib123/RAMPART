# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in python
**Pair ID:** 461_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `461_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```python
Lines 36-77 of the vulnerable file.

threat_level_mapping = {'High': '1', 'Medium': '2', 'Low': '3', 'Undefined': '4'}

descFilename = os.path.join(__path__[0], 'data/describeTypes.json')
with open(descFilename, 'r') as f:
    categories = json.loads(f.read())['result'].get('categories')

class StixParser():
    def __init__(self):
        super(StixParser, self).__init__()
        self.misp_event = MISPEvent()
        self.misp_event['Galaxy'] = []
        self.references = defaultdict(list)

    ################################################################################
    ##            LOADING & UTILITY FUNCTIONS USED BY BOTH SUBCLASSES.            ##
    ################################################################################

    # Load data from STIX document, and other usefull data
    def load_event(self, args, filename, from_misp, stix_version):
        self.outputname = '{}.json'.format(filename)
        if len(args) > 0 and args[0]:
            self.add_original_file(filename, args[0], stix_version)
        try:
            event_distribution = args[1]
            if not isinstance(event_distribution, int):
                event_distribution = int(event_distribution) if event_distribution.isdigit() else 5
        except IndexError:
            event_distribution = 5
        try:
            attribute_distribution = args[2]
            if attribute_distribution == 'event':
                attribute_distribution = event_distribution
            elif not isinstance(attribute_distribution, int):
                attribute_distribution = int(attribute_distribution) if attribute_distribution.isdigit() else event_distribution
        except IndexError:
            attribute_distribution = event_distribution
        self.misp_event.distribution = event_distribution
        self.__attribute_distribution = attribute_distribution
        self.from_misp = from_misp
        self.load_mapping()

    # Convert the MISP event we create from the STIX document into json format
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,16 +53,14 @@
     # Load data from STIX document, and other usefull data
     def load_event(self, args, filename, from_misp, stix_version):
         self.outputname = '{}.json'.format(filename)
-        if len(args) > 0 and args[0]:
-            self.add_original_file(filename, args[0], stix_version)
         try:
-            event_distribution = args[1]
+            event_distribution = args[0]
             if not isinstance(event_distribution, int):
                 event_distribution = int(event_distribution) if event_distribution.isdigit() else 5
         except IndexError:
             event_distribution = 5
         try:
-            attribute_distribution = args[2]
+            attribute_distribution = args[1]
             if attribute_distribution == 'event':
                 attribute_distribution = event_distribution
             elif not isinstance(attribute_distribution, int):
@@ -80,16 +78,6 @@
         eventDict = self.misp_event.to_json()
         with open(self.outputname, 'wt', encoding='utf-8') as f:
             f.write(eventDict)
-
-    def add_original_file(self, filename, original_filename, version):
-        with open(filename, 'rb') as f:
-            sample = base64.b64encode(f.read()).decode('utf-8')
-        original_file = MISPObject('original-imported-file')
-        original_file.add_attribute(**{'type': 'attachment', 'value': original_filename,
-                                       'object_relation': 'imported-sample', 'data': sample})
-        original_file.add_attribute(**{'type': 'text', 'object_relation': 'format',
-                                       'value': 'STIX {}'.format(version)})
-        self.misp_event.add_object(**original_file)
 
     # Load the mapping dictionary for STIX object types
     def load_mapping(self):
```
