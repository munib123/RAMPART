# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 2971_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2971_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 30-70 of the vulnerable file.

def index():
    return render_template("/login.html")

@app.route("/logout")
def logout():
    return render_template("/login.html")

@app.route("/login", methods=["POST"])
def login():
    id = request.form['id']
    if id == trape.stats_key:
        return json.dumps({'status':'OK', 'path' : trape.home_path, 'victim_path' : trape.victim_path, 'url_to_clone' : trape.url_to_clone, 'app_port' : trape.app_port, 'date_start' : trape.date_start, 'user_ip' : '127.0.0.1'});
    else:
      return json.dumps({'status':'NOPE', 'path' : '/'});

@app.route("/get_data", methods=["POST"])
def home_get_dat():
    d = db.sentences_stats('get_data')
    n = db.sentences_stats('all_networks')

    ('clean_online')
    rows = db.sentences_stats('get_clicks')
    c = rows[0][0]
    rows = db.sentences_stats('get_sessions')
    s = rows[0][0]
    rows = db.sentences_stats('get_online')
    o = rows[0][0]

    return json.dumps({'status' : 'OK', 'd' : d, 'n' : n, 'c' : c, 's' : s, 'o' : o});

@app.route("/get_preview", methods=["POST"])
def home_get_preview():
    vId = request.form['vId']
    d = db.sentences_stats('get_preview', vId)
    n = db.sentences_stats('id_networks', vId)
    return json.dumps({'status' : 'OK', 'vId' : vId, 'd' : d, 'n' : n});

@app.route("/get_title", methods=["POST"])
def home_get_title():
    opener = urllib2.build_opener()
    html = opener.open(trape.url_to_clone).read()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,12 +47,12 @@
     d = db.sentences_stats('get_data')
     n = db.sentences_stats('all_networks')
 
-    ('clean_online')
     rows = db.sentences_stats('get_clicks')
     c = rows[0][0]
     rows = db.sentences_stats('get_sessions')
     s = rows[0][0]
-    rows = db.sentences_stats('get_online')
+    vId = ('online', )
+    rows = db.sentences_stats('get_online', vId)
     o = rows[0][0]
 
     return json.dumps({'status' : 'OK', 'd' : d, 'n' : n, 'c' : c, 's' : s, 'o' : o});
@@ -60,8 +60,9 @@
 @app.route("/get_preview", methods=["POST"])
 def home_get_preview():
     vId = request.form['vId']
-    d = db.sentences_stats('get_preview', vId)
-    n = db.sentences_stats('id_networks', vId)
+    t = (vId,)
+    d = db.sentences_stats('get_preview', t)
+    n = db.sentences_stats('id_networks', t)
     return json.dumps({'status' : 'OK', 'vId' : vId, 'd' : d, 'n' : n});
 
 @app.route("/get_title", methods=["POST"])
```
