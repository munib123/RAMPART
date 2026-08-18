# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 3655_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3655_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 99-139 of the vulnerable file.

  if ( endptr == segment_begin ) {
    val = -1;
  }
  if ( errno == 0 || segment_begin == endptr ) {
    parsed_params.push_back( val );
  }

  parsed = true;
}

int Dispatcher::getparam( size_t N, int defaultval )
{
  int ret = defaultval;
  if ( !parsed ) {
    parse_params();
  }

  if ( parsed_params.size() > N ) {
    ret = parsed_params[ N ];
  }
  if ( ret < 1 ) ret = defaultval;

  return ret;
}

int Dispatcher::param_count( void )
{
  if ( !parsed ) {
    parse_params();
  }

  return parsed_params.size();
}

std::string Dispatcher::str( void )
{
  char assum[ 64 ];
  snprintf( assum, 64, "[dispatch=\"%s\" params=\"%s\"]",
	    dispatch_chars.c_str(), params.c_str() );
  return std::string( assum );
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -116,6 +116,11 @@
   if ( parsed_params.size() > N ) {
     ret = parsed_params[ N ];
   }
+
+  if ( ret > PARAM_MAX ) {
+    ret = defaultval;
+  }
+
   if ( ret < 1 ) ret = defaultval;
 
   return ret;
```
