# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 4621_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4621_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 1-21 of the vulnerable file.

from pathlib import Path
from urllib.parse import unquote
import base64
import json, os, requests, time, pytz, pymongo
from shutil import rmtree
from requests.exceptions import ConnectionError
from os.path import join, exists
from django.shortcuts import render
from django.core.serializers import serialize
from django.http import HttpResponse
from django.forms.models import model_to_dict
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from subprocess import Popen, PIPE
from gerapy import get_logger
from gerapy.server.core.response import JsonResponse
from gerapy.cmd.init import PROJECTS_FOLDER
from gerapy.server.server.settings import TIME_ZONE
from gerapy.server.core.models import Client, Project, Deploy, Monitor, Task
from gerapy.server.core.build import build_project, find_egg
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,4 @@
+import re
 from pathlib import Path
 from urllib.parse import unquote
 import base64
@@ -251,6 +252,8 @@
         configuration = json.dumps(data.get('configuration'), ensure_ascii=False)
         project.update(**{'configuration': configuration})
         
+        # for safe protection
+        project_name = re.sub('[\!\@\#\$\;\&\*\~\"\'\{\}\]\[\-\+\%\^]+', '', project_name)
         # execute generate cmd
         cmd = ' '.join(['gerapy', 'generate', project_name])
         p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
@@ -634,17 +637,15 @@
     if request.method == 'GET':
         client = Client.objects.get(id=client_id)
         scrapyd = get_scrapyd(client)
-        try:
-            result = scrapyd.list_jobs(project_name)
-            jobs = []
-            statuses = ['pending', 'running', 'finished']
-            for status in statuses:
-                for job in result.get(status):
-                    job['status'] = status
-                    jobs.append(job)
-            return JsonResponse(jobs)
-        except ConnectionError:
-            return JsonResponse({'message': 'Connect Error'}, status=500)
+        result = scrapyd.list_jobs(project_name)
+        jobs = []
+        statuses = ['pending', 'running', 'finished']
+        for status in statuses:
+            for job in result.get(status):
+                job['status'] = status
+                jobs.append(job)
+        return JsonResponse(jobs)
+    
 
 
 @api_view(['GET'])
@@ -663,21 +664,18 @@
         client = Client.objects.get(id=client_id)
         # get log url
         url = log_url(client.ip, client.port, project_name, spider_name, job_id)
-        try:
-            # get last 1000 bytes of log
-            response = requests.get(url, timeout=5, headers={
-                'Range': 'bytes=-1000'
-            }, auth=(client.username, client.password) if client.auth else None)
-            # Get encoding
-            encoding = response.apparent_encoding
-            # log not found
-            if response.status_code == 404:
-                return JsonResponse({'message': 'Log Not Found'}, status=404)
-            # bytes to string
-            text = response.content.decode(encoding, errors='replace')
-            return HttpResponse(text)
-        except requests.ConnectionError:
-            return JsonResponse({'message': 'Load Log Error'}, status=500)
+        # get last 1000 bytes of log
+        response = requests.get(url, timeout=5, headers={
+            'Range': 'bytes=-1000'
+        }, auth=(client.username, client.password) if client.auth else None)
+        # Get encoding
+        encoding = response.apparent_encoding
+        # log not found
+        if response.status_code == 404:
+            return JsonResponse({'message': 'Log Not Found'}, status=404)
+        # bytes to string
+        text = response.content.decode(encoding, errors='replace')
+        return HttpResponse(text)
 
 
 @api_view(['GET'])
@@ -693,12 +691,9 @@
     """
     if request.method == 'GET':
         client = Client.objects.get(id=client_id)
-        try:
-            scrapyd = get_scrapyd(client)
-            result = scrapyd.cancel(project_name, job_id)
-            return JsonResponse(result)
-        except ConnectionError:
-            return JsonResponse({'message': 'Connect Error'})
+        scrapyd = get_scrapyd(client)
+        result = scrapyd.cancel(project_name, job_id)
+        return JsonResponse(result)
 
 
 @api_view(['GET'])
@@ -706,12 +701,9 @@
 def del_version(request, client_id, project, version):
     if request.method == 'GET':
         client = Client.objects.get(id=client_id)
-        try:
-            scrapyd = get_scrapyd(client)
-            result = scrapyd.delete_version(project=project, version=version)
-            return JsonResponse(result)
-        except ConnectionError:
-            return JsonResponse({'message': 'Connect Error'})
+        scrapyd = get_scrapyd(client)
+        result = scrapyd.delete_version(project=project, version=version)
+        return JsonResponse(result)
 
 
 @api_view(['GET'])
@@ -719,12 +711,9 @@
 def del_project(request, client_id, project):
     if request.method == 'GET':
         client = Client.objects.get(id=client_id)
-        try:
-            scrapyd = get_scrapyd(client)
-            result = scrapyd.delete_project(project=project)
-            return JsonResponse(result)
-        except ConnectionError:
-            return JsonResponse({'message': 'Connect Error'})
+        scrapyd = get_scrapyd(client)
+        result = scrapyd.delete_project(project=project)
+        return JsonResponse(result)
 
 
 @api_view(['POST'])
@@ -829,18 +818,16 @@
     :return:
     """
     if request.method == 'POST':
-        try:
-            # delete job from DjangoJob
-            task = Task.objects.get(id=task_id)
-            clients = clients_of_task(task)
-            for client in clients:
-                job_id = get_job_id(client, task)
-                DjangoJob.objects.filter(name=job_id).delete()
-            # delete task
-            Task.objects.filter(id=task_id).delete()
-            return JsonResponse({'result': '1'})
-        except:
-            return JsonResponse({'result': '0'})
+        # delete job from DjangoJob
+        task = Task.objects.get(id=task_id)
+        clients = clients_of_task(task)
+        for client in clients:
+            job_id = get_job_id(client, task)
+            DjangoJob.objects.filter(name=job_id).delete()
+        # delete task
+        Task.objects.filter(id=task_id).delete()
+        return JsonResponse({'result': '1'})
+    
 
 
 @api_view(['GET'])
@@ -915,10 +902,7 @@
         url = unquote(base64.b64decode(url).decode('utf-8'))
         js = request.GET.get('js', 0)
         script = request.GET.get('script')
-        try:
-            response = requests.get(url, timeout=5)
-            response.encoding = response.apparent_encoding
-            html = process_html(response.text)
-            return HttpResponse(html)
-        except Exception as e:
-            return JsonResponse({'message': e.args}, status=500)
+        response = requests.get(url, timeout=5)
+        response.encoding = response.apparent_encoding
+        html = process_html(response.text)
+        return HttpResponse(html)
```
