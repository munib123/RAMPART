# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4608_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4608_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 111-163 of the vulnerable file.

            var find = matches(filter);
            return filterd(this.rules, find);
        }
    }
    RuleEngine.prototype.turn = function(state, filter) {
        var state = (state === "on" || state === "ON") ? true : false;
        var rules = this.findRules(filter);
        for (var i = 0, j = rules.length; i < j; i++) {
            rules[i].on = state;
        }
        this.sync();
    }
    RuleEngine.prototype.prioritize = function(priority, filter) {
        priority = parseInt(priority, 10);
        var rules = this.findRules(filter);
        for (var i = 0, j = rules.length; i < j; i++) {
            rules[i].priority = priority;
        }
        this.sync();
    }
    RuleEngine.prototype.toJSON = function() {
        var rules = this.rules;
        if (rules instanceof Array) {
            rules = rules.map(function(rule) {
                rule.condition = rule.condition.toString();
                rule.consequence = rule.consequence.toString();
                return rule;
            });
        } else if (typeof(rules) != "undefined") {
            rules.condition = rules.condition.toString();
            rules.consequence = rules.consequence.toString();
        }
        return rules;
    };
    RuleEngine.prototype.fromJSON = function(rules) {
        this.init();
        if (typeof(rules) == "string") {
            rules = JSON.parse(rules);
        }
        if (rules instanceof Array) {
            rules = rules.map(function(rule) {
                rule.condition = eval("(" + rule.condition + ")");
                rule.consequence = eval("(" + rule.consequence + ")");
                return rule;
            });
        } else if (rules !== null && typeof(rules) == "object") {
            rules.condition = eval("(" + rules.condition + ")");
            rules.consequence = eval("(" + rules.consequence + ")");
        }
        this.register(rules);
    };
    module.exports = RuleEngine;
}(module.exports));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -128,36 +128,5 @@
         }
         this.sync();
     }
-    RuleEngine.prototype.toJSON = function() {
-        var rules = this.rules;
-        if (rules instanceof Array) {
-            rules = rules.map(function(rule) {
-                rule.condition = rule.condition.toString();
-                rule.consequence = rule.consequence.toString();
-                return rule;
-            });
-        } else if (typeof(rules) != "undefined") {
-            rules.condition = rules.condition.toString();
-            rules.consequence = rules.consequence.toString();
-        }
-        return rules;
-    };
-    RuleEngine.prototype.fromJSON = function(rules) {
-        this.init();
-        if (typeof(rules) == "string") {
-            rules = JSON.parse(rules);
-        }
-        if (rules instanceof Array) {
-            rules = rules.map(function(rule) {
-                rule.condition = eval("(" + rule.condition + ")");
-                rule.consequence = eval("(" + rule.consequence + ")");
-                return rule;
-            });
-        } else if (rules !== null && typeof(rules) == "object") {
-            rules.condition = eval("(" + rules.condition + ")");
-            rules.consequence = eval("(" + rules.consequence + ")");
-        }
-        this.register(rules);
-    };
     module.exports = RuleEngine;
 }(module.exports));
```
