# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 2971_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2971_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 80-101 of the vulnerable file.


    @app.route("/redv")
    def redirectVictim():
        url = request.args.get('url')
        opener = urllib2.build_opener()
        headers = victim_headers()
        opener.addheaders = headers
        html = victim_inject_code(opener.open(url).read(), 'vscript')
        return html

    @app.route("/regv", methods=["POST"])
    def registerRequest():
        vrequest = victim_request(request.form['vId'], request.form['site'], request.form['fid'], request.form['name'], request.form['value'], request.form['sId'])
        db.sentences_victim('insert_requests', [vrequest, time.strftime("%Y-%m-%d - %H:%M:%S")], 2)
        utils.Go(utils.Color['white'] + "[" + utils.Color['greenBold'] + "=" + utils.Color['white'] + "]" + " " + 'Receiving data from: ' + utils.Color['green'] + vrequest.id + utils.Color['white']  + ' ' + 'on' + ' ' + utils.Color['blue'] + vrequest.site + utils.Color['white'] + '\t\n' + vrequest.fid + '\t' + vrequest.name + ':\t' + vrequest.value)
        return json.dumps({'status' : 'OK', 'vId' : vrequest.id});

    @app.route("/tping", methods=["POST"])
    def receivePing():
        vrequest = request.form['id']
        db.sentences_victim('report_online', [vrequest])
        return json.dumps({'status' : 'OK', 'vId' : vrequest});
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,5 +97,5 @@
     @app.route("/tping", methods=["POST"])
     def receivePing():
         vrequest = request.form['id']
-        db.sentences_victim('report_online', [vrequest])
+        db.sentences_victim('report_online', [vrequest], 2)
         return json.dumps({'status' : 'OK', 'vId' : vrequest});
```
