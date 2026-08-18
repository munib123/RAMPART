# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 3655_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3655_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 60-100 of the vulnerable file.

    dispatch_map_t CSI;
    dispatch_map_t control;

    DispatchRegistry() : escape(), CSI(), control() {}
  };

  DispatchRegistry & get_global_dispatch_registry( void );

  class Dispatcher {
  private:
    std::string params;
    std::vector<int> parsed_params;
    bool parsed;

    std::string dispatch_chars;
    std::vector<wchar_t> OSC_string; /* only used to set the window title */

    void parse_params( void );

  public:
    std::string terminal_to_host; /* this is the reply string */

    Dispatcher();
    int getparam( size_t N, int defaultval );
    int param_count( void );

    void newparamchar( const Parser::Param *act );
    void collect( const Parser::Collect *act );
    void clear( const Parser::Clear *act );
    
    std::string str( void );

    void dispatch( Function_Type type, const Parser::Action *act, Framebuffer *fb );
    std::string get_dispatch_chars( void ) { return dispatch_chars; }
    std::vector<wchar_t> get_OSC_string( void ) { return OSC_string; }

    void OSC_put( const Parser::OSC_Put *act );
    void OSC_start( const Parser::OSC_Start *act );
    void OSC_dispatch( const Parser::OSC_End *act, Framebuffer *fb );

    bool operator==( const Dispatcher &x ) const;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -77,6 +77,9 @@
     void parse_params( void );
 
   public:
+    static const int PARAM_MAX = 65535;
+    /* prevent evil escape sequences from causing long loops */
+
     std::string terminal_to_host; /* this is the reply string */
 
     Dispatcher();
```
