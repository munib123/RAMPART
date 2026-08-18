# CrossVul Fix Pair: Incorrect Authorization in python
**Pair ID:** 4098_0
**Vulnerability Class:** Incorrect Authorization
**CWE:** CWE-863
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4098_0`)

## Vulnerability Information & PoC

## Description
Incorrect Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```python
Lines 363-403 of the vulnerable file.

        for (payer, amount, owers, subject) in operations:
            bill = Bill()
            bill.payer_id = members[payer].id
            bill.what = subject
            bill.owers = [members[name] for name in owers]
            bill.amount = amount
            bill.original_currency = "EUR"
            bill.converted_amount = amount

            db.session.add(bill)

        db.session.commit()
        return project


class Person(db.Model):
    class PersonQuery(BaseQuery):
        def get_by_name(self, name, project):
            return (
                Person.query.filter(Person.name == name)
                .filter(Project.id == project.id)
                .one()
            )

        def get(self, id, project=None):
            if not project:
                project = g.project
            return (
                Person.query.filter(Person.id == id)
                .filter(Project.id == project.id)
                .one()
            )

    query_class = PersonQuery

    # Direct SQLAlchemy-Continuum to track changes to this model
    __versioned__ = {}

    __table_args__ = {"sqlite_autoincrement": True}

    id = db.Column(db.Integer, primary_key=True)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -380,7 +380,7 @@
         def get_by_name(self, name, project):
             return (
                 Person.query.filter(Person.name == name)
-                .filter(Project.id == project.id)
+                .filter(Person.project_id == project.id)
                 .one()
             )
 
@@ -389,7 +389,7 @@
                 project = g.project
             return (
                 Person.query.filter(Person.id == id)
-                .filter(Project.id == project.id)
+                .filter(Person.project_id == project.id)
                 .one()
             )
 
```
