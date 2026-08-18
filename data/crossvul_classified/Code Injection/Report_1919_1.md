# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1919_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1919_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 1677-1736 of the vulnerable file.

       margin-bottom: 1em;
       -webkit-border-radius: 4px;
       border-radius: 4px;
       border: 1px solid;
       padding: .5em;
   }
   div[ng-controller^=Good] {
       border-color: #d6e9c6;
       background-color: #dff0d8;
       color: #3c763d;
   }
   div[ng-controller^=Bad] {
       border-color: #ebccd1;
       background-color: #f2dede;
       color: #a94442;
       margin-bottom: 0;
   }
   </file>
 </example>
 */
function angularInit(element, bootstrap) {
	var appElement,
		module,
		config = {};

	// The element `element` has priority over any other element.
	forEach(ngAttrPrefixes, function (prefix) {
		var name = prefix + "app";

		if (!appElement && element.hasAttribute && element.hasAttribute(name)) {
			appElement = element;
			module = element.getAttribute(name);
		}
	});
	forEach(ngAttrPrefixes, function (prefix) {
		var name = prefix + "app";
		var candidate;

		if (
			!appElement &&
			(candidate = element.querySelector("[" + name.replace(":", "\\:") + "]"))
		) {
			appElement = candidate;
			module = candidate.getAttribute(name);
		}
	});
	if (appElement) {
		if (!isAutoBootstrapAllowed) {
			window.console.error(
				"Angular: disabling automatic bootstrap. <script> protocol indicates " +
					"an extension, document.location.href does not match."
			);
			return;
		}
		config.strictDi = getNgAttribute(appElement, "strict-di") !== null;
		bootstrap(appElement, module ? [module] : [], config);
	}
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1694,44 +1694,6 @@
    </file>
  </example>
  */
-function angularInit(element, bootstrap) {
-	var appElement,
-		module,
-		config = {};
-
-	// The element `element` has priority over any other element.
-	forEach(ngAttrPrefixes, function (prefix) {
-		var name = prefix + "app";
-
-		if (!appElement && element.hasAttribute && element.hasAttribute(name)) {
-			appElement = element;
-			module = element.getAttribute(name);
-		}
-	});
-	forEach(ngAttrPrefixes, function (prefix) {
-		var name = prefix + "app";
-		var candidate;
-
-		if (
-			!appElement &&
-			(candidate = element.querySelector("[" + name.replace(":", "\\:") + "]"))
-		) {
-			appElement = candidate;
-			module = candidate.getAttribute(name);
-		}
-	});
-	if (appElement) {
-		if (!isAutoBootstrapAllowed) {
-			window.console.error(
-				"Angular: disabling automatic bootstrap. <script> protocol indicates " +
-					"an extension, document.location.href does not match."
-			);
-			return;
-		}
-		config.strictDi = getNgAttribute(appElement, "strict-di") !== null;
-		bootstrap(appElement, module ? [module] : [], config);
-	}
-}
 
 /**
  * @ngdoc function
@@ -3232,11 +3194,12 @@
 			intoId = intoId || this.nextId();
 			this.if_(
 				"i",
-				this.lazyAssign(intoId, this.computedMember("i", ast.watchId)),
+				this.lazyAssign(intoId, this.unsafeComputedMember("i", ast.watchId)),
 				this.lazyRecurse(ast, intoId, nameId, recursionFn, create, true)
 			);
 			return;
 		}
+
 		switch (ast.type) {
 			case AST.Program:
 				forEach(ast.body, function (expression, pos) {
@@ -3356,11 +3319,20 @@
 					undefined,
 					function () {
 						var member = null;
+						const inAssignment = self.current().inAssignment;
 						if (ast.computed) {
 							right = self.nextId();
-							member = self.computedMember(left, right);
+							if (inAssignment || self.state.computing === "assign") {
+								member = self.unsafeComputedMember(left, right);
+							} else {
+								member = self.computedMember(left, right);
+							}
 						} else {
-							member = self.nonComputedMember(left, ast.property.name);
+							if (inAssignment || self.state.computing === "assign") {
+								member = self.unsafeNonComputedMember(left, ast.property.name);
+							} else {
+								member = self.nonComputedMember(left, ast.property.name);
+							}
 							right = ast.property.name;
 						}
 
@@ -3447,7 +3419,13 @@
 								if (left.name) {
 									var x = self.member(left.context, left.name, left.computed);
 									expression =
-										x + ".call(" + [left.context].concat(args).join(",") + ")";
+										"(" +
+										x +
+										" === null ? null : " +
+										self.unsafeMember(left.context, left.name, left.computed) +
+										".call(" +
+										[left.context].concat(args).join(",") +
+										"))";
 								} else {
 									expression = right + "(" + args.join(",") + ")";
 								}
@@ -3464,6 +3442,7 @@
 			case AST.AssignmentExpression:
 				right = this.nextId();
 				left = {};
+				self.current().inAssignment = true;
 				this.recurse(
 					ast.left,
 					undefined,
@@ -3489,9 +3468,13 @@
 								recursionFn(intoId || expression);
 							}
 						);
+						self.current().inAssignment = false;
+						self.recurse(ast.right, right);
+						self.current().inAssignment = true;
 					},
 					1
 				);
+				self.current().inAssignment = false;
 				break;
 			case AST.ArrayExpression:
 				args = [];
@@ -3532,7 +3515,10 @@
 						}
 						right = self.nextId();
 						self.recurse(property.value, right);
-						self.assign(self.member(intoId, left, property.computed), right);
+						self.assign(
+							self.unsafeMember(intoId, left, property.computed),
+							right
+						);
 					});
 				} else {
 					forEach(ast.properties, function (property) {
@@ -3666,8 +3652,34 @@
 		return expr;
 	},
 
+	unsafeComputedMember: function (left, right) {
+		return left + "[" + right + "]";
+	},
+	unsafeNonComputedMember: function (left, right) {
+		return this.nonComputedMember(left, right);
+	},
+
 	computedMember: function (left, right) {
-		return left + "[" + right + "]";
+		if (this.state.computing === "assign") {
+			return this.unsafeComputedMember(left, right);
+		}
+		// return left + "[" + right + "]";
+		return (
+			"(" +
+			left +
+			".hasOwnProperty(" +
+			right +
+			") ? " +
+			left +
+			"[" +
+			right +
+			"] : null)"
+		);
+	},
+
+	unsafeMember: function (left, right, computed) {
+		if (computed) return this.unsafeComputedMember(left, right);
+		return this.unsafeNonComputedMember(left, right);
 	},
 
 	member: function (left, right, computed) {
@@ -3827,6 +3839,7 @@
 					right = ast.property.name;
 				}
 				if (ast.computed) right = this.recurse(ast.property);
+
 				return ast.computed
 					? this.computedMember(left, right, context, create)
 					: this.nonComputedMember(left, right, context, create);
```
