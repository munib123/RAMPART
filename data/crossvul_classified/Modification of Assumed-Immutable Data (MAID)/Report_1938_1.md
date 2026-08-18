# CrossVul Fix Pair: Improperly Controlled Modification of Dynamically-Determined Object Attributes in javascript
**Pair ID:** 1938_1
**Vulnerability Class:** Modification of Assumed-Immutable Data (MAID)
**CWE:** CWE-915
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1938_1`)

## Vulnerability Information & PoC

## Description
Improperly Controlled Modification of Dynamically-Determined Object Attributes - If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability.

## Vulnerable Code
```javascript
Lines 21-49 of the vulnerable file.

		},
		{
			"input": [{}, "test.hello", "random"],
			"output": {"test": {"hello": "random"}}
		},
		{
			"input": [{}, "test.hello.test", "random"],
			"output": {"test": {"hello": {"test": "random"}}}
		},
		{
			"input": [{"data": [{"id": "hello world"}]}, "data.0.id", "random"],
			"output": {"data": [{"id": "random"}]}
		},
		{
			"input": [{"data": [{"id": "hello world"}]}, "data.1.id", "random"],
			"output": {"data": [{"id": "hello world"}, {"id": "random"}]}
		},
		{
			"input": [{"data": []}, "data.0", {"hello": "world"}],
			"output": {"data": [{"hello": "world"}]}
		}
	];

	tests.forEach((test) => {
		it(`Should return ${test.output} for ${test.input}`, () => {
			expect(utils.object.set(...test.input)).to.eql(test.output);
		});
	});
});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -38,6 +38,14 @@
 		{
 			"input": [{"data": []}, "data.0", {"hello": "world"}],
 			"output": {"data": [{"hello": "world"}]}
+		},
+		{
+			"input": [{}, "__proto__", "Hello"],
+			"output": {}
+		},
+		{
+			"input": [{}, "constructor", "Hello"],
+			"output": {}
 		}
 	];
 
```
