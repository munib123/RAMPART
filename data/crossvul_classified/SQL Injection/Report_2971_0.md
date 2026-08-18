# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in python
**Pair ID:** 2971_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2971_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```python
Lines 11-51 of the vulnerable file.

#
# Copyright 2017 by boxug / <hey@boxug.com>
#**
import sqlite3

class Database(object):
    def __init__(self):     
        self.conn = sqlite3.connect("database.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        
    def loadDatabase(self):
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS "geo" ( `id` TEXT, `city` TEXT, `country_code` TEXT, `country_name` TEXT, `ip` TEXT, `latitude` TEXT, `longitude` TEXT, `metro_code` TEXT, `region_code` TEXT, `region_name` TEXT, `time_zone` TEXT, `zip_code` TEXT, `isp` TEXT, `ua` TEXT, PRIMARY KEY(`id`) )""")
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS "networks" ( `id` TEXT, `ip` TEXT, `public_ip` INTEGER, `network` TEXT, `date` TEXT )""")
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS "requests" ( `id` TEXT, `user_id` TEXT, `site` TEXT, `fid` TEXT, `name` TEXT, `value` TEXT, `date` TEXT )""")
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS "victims" ( `id` TEXT, `ip` TEXT, `date` TEXT, `time` REAL, `bVersion` TEXT, `browser` TEXT, `device` TEXT, `cpu` TEXT, `ports` TEXT, `status`  TEXT )""")
        self.cursor.execute("""CREATE TABLE IF NOT EXISTS "clicks" ( `id` TEXT, `site` TEXT, `date` TEXT )""")
        self.conn.commit()
        return True

    def sql_execute(self, sentence):
        self.cursor.execute(sentence)
        return self.cursor.fetchall()

    def sql_one_row(self, sentence, column):
        self.cursor.execute(sentence)
        return self.cursor.fetchone()[column]

    def sql_insert(self, sentence):
        self.cursor.execute(sentence)
        self.conn.commit()
        return True

    def prop_sentences_stats(self, type, vId = None):
        return {
            'get_data' : "SELECT victims.*, geo.*, victims.ip AS ip_local, COUNT(clicks.id) FROM victims INNER JOIN geo ON victims.id = geo.id LEFT JOIN clicks ON clicks.id = victims.id GROUP BY victims.id ORDER BY victims.time DESC",
            'all_networks' : "SELECT networks.* FROM networks ORDER BY id",
            'get_preview' : "SELECT victims.*, geo.*, victims.ip AS ip_local FROM victims INNER JOIN geo ON victims.id = geo.id WHERE victims.id = '%s'" % (vId),
            'id_networks' : "SELECT networks.* FROM networks WHERE id = '%s'" % (vId),
            'get_requests' : "SELECT requests.*, geo.ip FROM requests INNER JOIN geo on geo.id = requests.user_id ORDER BY requests.date DESC, requests.id ",
            'get_sessions' : "SELECT COUNT(*) AS Total FROM networks",
            'get_clicks' : "SELECT COUNT(*) AS Total FROM clicks",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,74 +28,91 @@
         return True
 
     def sql_execute(self, sentence):
-        self.cursor.execute(sentence)
+    	if type(sentence) is str:
+        	self.cursor.execute(sentence)
+    	else:
+        	self.cursor.execute(sentence[0], sentence[1])
         return self.cursor.fetchall()
 
     def sql_one_row(self, sentence, column):
-        self.cursor.execute(sentence)
+        if type(sentence) is str:
+        	self.cursor.execute(sentence)
+    	else:
+        	self.cursor.execute(sentence[0], sentence[1])	
         return self.cursor.fetchone()[column]
 
     def sql_insert(self, sentence):
-        self.cursor.execute(sentence)
+        if type(sentence) is str:
+        	self.cursor.execute(sentence)
+    	else:
+        	self.cursor.execute(sentence[0], sentence[1])
         self.conn.commit()
         return True
 
     def prop_sentences_stats(self, type, vId = None):
         return {
-            'get_data' : "SELECT victims.*, geo.*, victims.ip AS ip_local, COUNT(clicks.id) FROM victims INNER JOIN geo ON victims.id = geo.id LEFT JOIN clicks ON clicks.id = victims.id GROUP BY victims.id ORDER BY victims.time DESC",
-            'all_networks' : "SELECT networks.* FROM networks ORDER BY id",
-            'get_preview' : "SELECT victims.*, geo.*, victims.ip AS ip_local FROM victims INNER JOIN geo ON victims.id = geo.id WHERE victims.id = '%s'" % (vId),
-            'id_networks' : "SELECT networks.* FROM networks WHERE id = '%s'" % (vId),
-            'get_requests' : "SELECT requests.*, geo.ip FROM requests INNER JOIN geo on geo.id = requests.user_id ORDER BY requests.date DESC, requests.id ",
-            'get_sessions' : "SELECT COUNT(*) AS Total FROM networks",
-            'get_clicks' : "SELECT COUNT(*) AS Total FROM clicks",
-            'get_online' : "SELECT COUNT(*) AS Total FROM victims WHERE status = '%s'" % ('online')
+        	'get_data' : "SELECT victims.*, geo.*, victims.ip AS ip_local, COUNT(clicks.id) FROM victims INNER JOIN geo ON victims.id = geo.id LEFT JOIN clicks ON clicks.id = victims.id GROUP BY victims.id ORDER BY victims.time DESC",
+        	'all_networks' : "SELECT networks.* FROM networks ORDER BY id",
+        	'get_preview' : ("SELECT victims.*, geo.*, victims.ip AS ip_local FROM victims INNER JOIN geo ON victims.id = geo.id WHERE victims.id = ?" , vId),
+        	'id_networks' : ("SELECT networks.* FROM networks WHERE id = ?", vId),
+        	'get_requests' : "SELECT requests.*, geo.ip FROM requests INNER JOIN geo on geo.id = requests.user_id ORDER BY requests.date DESC, requests.id ",
+        	'get_sessions' : "SELECT COUNT(*) AS Total FROM networks",
+        	'get_clicks' : "SELECT COUNT(*) AS Total FROM clicks",
+        	'get_online' : ("SELECT COUNT(*) AS Total FROM victims WHERE status = ?", vId)
         }.get(type, False)
 
     def sentences_stats(self, type, vId = None):
-        return self.sql_execute(self.prop_sentences_stats(type, vId))
+    	return self.sql_execute(self.prop_sentences_stats(type, vId))
 
     def prop_sentences_victim(self, type, data = None):
         if type == 'count_victim':
-            return "SELECT COUNT(*) AS C FROM victims WHERE id = '%s'" % (data)
+        	t = (data,)
+        	return ("SELECT COUNT(*) AS C FROM victims WHERE id = ?" , t)
         elif type == 'count_times':
-            return "SELECT COUNT(*) AS C FROM clicks WHERE id = '%s'" % (data)
+        	t = (data,)
+        	return ("SELECT COUNT(*) AS C FROM clicks WHERE id = ?" , t)
         elif type == 'update_victim':
-            return "UPDATE victims SET ip = '%s', date = '%s', bVersion = '%s', browser = '%s', device = '%s', ports = '%s', time = '%s', cpu = '%s', status = '%s' WHERE id = '%s'" % (data[0].ip, data[0].date, data[0].version, data[0].browser, data[0].device, data[0].ports, data[2], data[0].cpu, 'online', data[1])
+        	t = (data[0].ip, data[0].date, data[0].version, data[0].browser, data[0].device, data[0].ports, data[2], data[0].cpu, 'online', data[1],)
+        	return ("UPDATE victims SET ip = ?, date = ?, bVersion = ?, browser = ?, device = ?, ports = ?, time = ?, cpu = ?, status = ? WHERE id = ?", t)
         elif type == 'update_victim_geo':
-            return "UPDATE geo SET city = '%s', country_code = '%s', country_name = '%s', ip = '%s', latitude = '%s', longitude = '%s', metro_code = '%s', region_code = '%s', region_name = '%s', time_zone = '%s', zip_code = '%s', isp = '%s', ua='%s' WHERE id = '%s'" % (data[0].city, data[0].country_code, data[0].country_name, data[0].ip, data[0].latitude, data[0].longitude, data[0].metro_code, data[0].region_code, data[0].region_name, data[0].time_zone, data[0].zip_code, data[0].isp, data[0].ua, data[1])
+        	t = (data[0].city, data[0].country_code, data[0].country_name, data[0].ip, data[0].latitude, data[0].longitude, data[0].metro_code, data[0].region_code, data[0].region_name, data[0].time_zone, data[0].zip_code, data[0].isp, data[0].ua, data[1],)
+        	return ("UPDATE geo SET city = ?, country_code = ?, country_name = ?, ip = ?, latitude = ?, longitude = ?, metro_code = ?, region_code = ?, region_name = ?, time_zone = ?, zip_code = ?, isp = ?, ua=? WHERE id = ?", t)
         elif type == 'insert_victim':
-            return "INSERT INTO victims(id, ip, date, bVersion, browser, device, ports, time, cpu, status) VALUES('%s','%s', '%s','%s', '%s','%s', '%s', '%s', '%s', '%s')" % (data[1], data[0].ip, data[0].date, data[0].version, data[0].browser, data[0].device, data[0].ports, data[2], data[0].cpu, 'online')
+        	t = (data[1], data[0].ip, data[0].date, data[0].version, data[0].browser, data[0].device, data[0].ports, data[2], data[0].cpu, 'online',)
+        	return ("INSERT INTO victims(id, ip, date, bVersion, browser, device, ports, time, cpu, status) VALUES(?,?, ?,?, ?,?, ?, ?, ?, ?)", t)
         elif type == 'insert_victim_geo':
-            return "INSERT INTO geo(id, city, country_code, country_name, ip, latitude, longitude, metro_code, region_code, region_name, time_zone, zip_code, isp, ua) VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"  % (data[1], data[0].city, data[0].country_code, data[0].country_name, data[0].ip, data[0].latitude, data[0].longitude, data[0].metro_code, data[0].region_code, data[0].region_name, data[0].time_zone, data[0].zip_code, data[0].isp, data[0].ua)
+        	t = (data[1], data[0].city, data[0].country_code, data[0].country_name, data[0].ip, data[0].latitude, data[0].longitude, data[0].metro_code, data[0].region_code, data[0].region_name, data[0].time_zone, data[0].zip_code, data[0].isp, data[0].ua,)
+        	return ("INSERT INTO geo(id, city, country_code, country_name, ip, latitude, longitude, metro_code, region_code, region_name, time_zone, zip_code, isp, ua) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" , t)
         elif type == 'count_victim_network':
-            return "SELECT COUNT(*) AS C FROM networks WHERE id = '%s' AND network = '%s'" % (data[0], data[1])
+        	return ("SELECT COUNT(*) AS C FROM networks WHERE id = ? AND network = ?", (data[0], data[1],))
         elif type == 'delete_networks':
-            return "DELETE FROM networks WHERE id = '%s'" % (data[0])
+        	return ("DELETE FROM networks WHERE id = ?", (data[0],))
         elif type == 'update_network':
-            return "UPDATE networks SET date = '%s' WHERE id = '%s' AND network = '%s'" % (data[2], data[0], data[1])
+        	return ("UPDATE networks SET date = ? WHERE id = ? AND network = ?" , (data[2], data[0], data[1],))
         elif type == 'insert_networks':
-            return "INSERT INTO networks(id, public_ip, ip, network, date) VALUES('%s','%s', '%s', '%s','%s')" % (data[0], data[1], data[2], data[3], data[4])
+        	t = (data[0], data[1], data[2], data[3], data[4],)
+        	return ("INSERT INTO networks(id, public_ip, ip, network, date) VALUES(?,?, ?, ?,?)" , t)
... (diff truncated)
```
