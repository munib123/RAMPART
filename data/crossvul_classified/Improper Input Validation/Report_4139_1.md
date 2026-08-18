# CrossVul Fix Pair: Improper Input Validation in go
**Pair ID:** 4139_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4139_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```go
Lines 1-23 of the vulnerable file.

/*
Copyright The Helm Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package chart

// ValidationError represents a data validation error.
type ValidationError string

func (v ValidationError) Error() string {
	return "validation: " + string(v)
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -15,9 +15,16 @@
 
 package chart
 
+import "fmt"
+
 // ValidationError represents a data validation error.
 type ValidationError string
 
 func (v ValidationError) Error() string {
 	return "validation: " + string(v)
 }
+
+// ValidationErrorf takes a message and formatting options and creates a ValidationError
+func ValidationErrorf(msg string, args ...interface{}) ValidationError {
+	return ValidationError(fmt.Sprintf(msg, args...))
+}
```
