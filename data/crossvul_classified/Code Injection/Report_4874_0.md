# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4874_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4874_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 32-72 of the vulnerable file.

var configuration = {
	directory      : "locales/",
	extension      : ".json",
	objectNotation : "."
};

/**
 * Configure the express routes through which translations are served.
 * @param app
 * @param {Object} [configObject]
 */
var configure = function( app, configObject ) {
	if( typeof configObject !== "undefined" ) {
		configuration.directory = configObject.directory || configuration.directory;
		configuration.extension = configObject.extension || configuration.extension;
		configuration.objectNotation = configObject.objectNotation || configuration.objectNotation;
	}

	// Register routes
	app.get( "/i18n/:locale", i18nRoutes.i18n );
	app.get( "/i18n/:locale/:phrase", i18nRoutes.translate );
};

/**
 * Middleware to allow retrieval of users locale in the template engine.
 * @param {Object} request
 * @param {Object} response
 * @param {Function} [next]
 */
var getLocale = function( request, response, next ) {
	response.locals.i18n = {
		getLocale : function() {
			return i18n.getLocale.apply( request, arguments );
		}
	};

	// For backwards compatibility, also define "acceptedLanguage".
	response.locals.acceptedLanguage = response.locals.i18n.getLocale;

	if( typeof next !== "undefined" ) {
		next();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,10 @@
 
 	// Register routes
 	app.get( "/i18n/:locale", i18nRoutes.i18n );
-	app.get( "/i18n/:locale/:phrase", i18nRoutes.translate );
+
+	if( process.env.NODE_ENV === "development" ) {
+		app.get( "/i18n/:locale/:phrase", i18nRoutes.translate );
+	}
 };
 
 /**
```
