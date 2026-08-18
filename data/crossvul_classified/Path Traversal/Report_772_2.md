# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in json
**Pair ID:** 772_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `772_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```json
Lines 1-25 of the vulnerable file.

{
  "common": {
    "name": "admin",
    "title": "Admin",
    "version": "3.6.7",
    "news": {
      "3.6.7": {
        "en": "Add Node.JS version check to popup messages",
        "de": "Node.JS-Versionsprüfung zu Popup-Nachrichten hinzufügen",
        "ru": "Добавить проверку версии Node.JS во всплывающие сообщения",
        "pt": "Adicione a verificação da versão do Node.JS às mensagens pop-up",
        "nl": "Voeg Node.JS versiecontrole toe aan pop-upberichten",
        "fr": "Ajouter la vérification de la version de Node.JS aux messages contextuels",
        "it": "Aggiungi il controllo versione Node.JS ai messaggi popup",
        "es": "Agregar verificación de versión de Node.JS a mensajes emergentes",
        "pl": "Dodaj sprawdzanie wersji Node.JS do wyskakujących wiadomości",
        "zh-cn": "将Node.JS版本检查添加到弹出消息"
      },
      "3.6.6": {
        "en": "update some words translation",
        "de": "Aktualisieren Sie einige Wörter Übersetzung",
        "ru": "обновить перевод некоторых слов",
        "pt": "atualizar algumas palavras tradução",
        "nl": "update enkele woorden vertaling",
        "fr": "mettre à jour la traduction de quelques mots",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2,7 +2,7 @@
   "common": {
     "name": "admin",
     "title": "Admin",
-    "version": "3.6.7",
+    "version": "3.6.8",
     "news": {
       "3.6.7": {
         "en": "Add Node.JS version check to popup messages",
@@ -16,7 +16,18 @@
         "pl": "Dodaj sprawdzanie wersji Node.JS do wyskakujących wiadomości",
         "zh-cn": "将Node.JS版本检查添加到弹出消息"
       },
-      "3.6.6": {
+      "3.6.7": {
+        "en": "Add Node.JS version check to popup messages",
+        "de": "Node.JS-Versionsprüfung zu Popup-Nachrichten hinzufügen",
+        "ru": "Добавить проверку версии Node.JS во всплывающие сообщения",
+        "pt": "Adicione a verificação da versão do Node.JS às mensagens pop-up",
+        "nl": "Voeg Node.JS versiecontrole toe aan pop-upberichten",
+        "fr": "Ajouter la vérification de la version de Node.JS aux messages contextuels",
+        "it": "Aggiungi il controllo versione Node.JS ai messaggi popup",
+        "es": "Agregar verificación de versión de Node.JS a mensajes emergentes",
+        "pl": "Dodaj sprawdzanie wersji Node.JS do wyskakujących wiadomości",
+        "zh-cn": "将Node.JS版本检查添加到弹出消息"
+      },"3.6.6": {
         "en": "update some words translation",
         "de": "Aktualisieren Sie einige Wörter Übersetzung",
         "ru": "обновить перевод некоторых слов",
@@ -87,7 +98,7 @@
         "es": "Integración del adaptador de información",
         "pl": "Integracja adaptera informacyjnego",
         "zh-cn": "信息适配器集成"
-      },    
+      },
       "3.6.0": {
         "en": "Added Chinese translations\nNew informative states added about updates",
         "de": "Chinesische Übersetzungen hinzugefügt\nNeue Informationsstände zu Updates hinzugefügt",
@@ -162,7 +173,7 @@
       "fr": "docs/fr/admin.md",
       "it": "docs/it/admin.md",
       "pl": "docs/pl/admin.md",
-      "zh-cn": "docs/zh-cn/admin.md"            
+      "zh-cn": "docs/zh-cn/admin.md"
     },
     "materialize": true,
     "mode": "daemon",
```
