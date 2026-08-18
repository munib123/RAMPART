# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 117_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `117_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 203-228 of the vulnerable file.

    _MAX_AAD_BYTES = (2 ** 64) // 8

    def __init__(self, initialization_vector, tag=None, min_tag_length=16):
        # len(initialization_vector) must in [1, 2 ** 64), but it's impossible
        # to actually construct a bytes object that large, so we don't check
        # for it
        if not isinstance(initialization_vector, bytes):
            raise TypeError("initialization_vector must be bytes")
        self._initialization_vector = initialization_vector
        if tag is not None:
            if not isinstance(tag, bytes):
                raise TypeError("tag must be bytes or None")
            if min_tag_length < 4:
                raise ValueError("min_tag_length must be >= 4")
            if len(tag) < min_tag_length:
                raise ValueError(
                    "Authentication tag must be {0} bytes or longer.".format(
                        min_tag_length)
                )
        self._tag = tag

    tag = utils.read_only_property("_tag")
    initialization_vector = utils.read_only_property("_initialization_vector")

    def validate_for_algorithm(self, algorithm):
        _check_aes_key_length(self, algorithm)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -220,6 +220,7 @@
                         min_tag_length)
                 )
         self._tag = tag
+        self._min_tag_length = min_tag_length
 
     tag = utils.read_only_property("_tag")
     initialization_vector = utils.read_only_property("_initialization_vector")
```
