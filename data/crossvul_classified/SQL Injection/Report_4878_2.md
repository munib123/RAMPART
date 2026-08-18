# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in javascript
**Pair ID:** 4878_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4878_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```javascript
Lines 573-613 of the vulnerable file.

            }
          } else {
            if (isSubQuery && !(t[0] instanceof Model) && !(t[0].model instanceof Model)) {
              subQueryOrder.push(this.quote(t, model));
            }
            mainQueryOrder.push(this.quote(t, model));
          }
        }.bind(this));
      } else {
        mainQueryOrder.push(options.order);
      }
    }

    if (options.limit || options.offset) {
      if (!options.order || (options.include && !subQueryOrder.length)) {
        fragment += (options.order && !isSubQuery) ? ', ' : ' ORDER BY ';
        fragment += this.quoteIdentifier(model.primaryKeyField);
      }

      if (options.offset || options.limit) {
        fragment += ' OFFSET ' + offset + ' ROWS';
      }

      if (options.limit) {
        fragment += ' FETCH NEXT ' + options.limit + ' ROWS ONLY';
      }
    }

    return fragment;
  },

  booleanValue: function(value) {
    return !!value ? 1 : 0;
  }
};

// private methods
function wrapSingleQuote(identifier){
  return Utils.addTicks(identifier, "'");
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -590,11 +590,11 @@
       }
 
       if (options.offset || options.limit) {
-        fragment += ' OFFSET ' + offset + ' ROWS';
+        fragment += ' OFFSET ' + this.escape(offset) + ' ROWS';
       }
 
       if (options.limit) {
-        fragment += ' FETCH NEXT ' + options.limit + ' ROWS ONLY';
+        fragment += ' FETCH NEXT ' + this.escape(options.limit) + ' ROWS ONLY';
       }
     }
 
```
