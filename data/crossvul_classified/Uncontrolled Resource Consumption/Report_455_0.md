# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 455_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `455_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 1706-1749 of the vulnerable file.

      return SASS_MEMORY_NEW(String_Quoted, pstate, lexed);
    }

    if (lex< sequence < exactly <'#'>, identifier > >())
    { return SASS_MEMORY_NEW(String_Quoted, pstate, lexed); }

    // also handle the 10em- foo special case
    // alternatives < exactly < '.' >, .. > -- `1.5em-.75em` is split into a list, not a binary expression
    if (lex< sequence< dimension, optional< sequence< exactly<'-'>, lookahead< alternatives < space > > > > > >())
    { return lexed_dimension(lexed); }

    if (lex< sequence< static_component, one_plus< strict_identifier > > >())
    { return SASS_MEMORY_NEW(String_Constant, pstate, lexed); }

    if (lex< number >())
    { return lexed_number(lexed); }

    if (lex< variable >())
    { return SASS_MEMORY_NEW(Variable, pstate, Util::normalize_underscores(lexed)); }

    // Special case handling for `%` proceeding an interpolant.
    if (lex< sequence< exactly<'%'>, optional< percentage > > >())
    { return SASS_MEMORY_NEW(String_Constant, pstate, lexed); }

    css_error("Invalid CSS", " after ", ": expected expression (e.g. 1px, bold), was ");

    // unreachable statement
    return 0;
  }

  // this parses interpolation inside other strings
  // means the result should later be quoted again
  String_Obj Parser::parse_interpolated_chunk(Token chunk, bool constant, bool css)
  {
    const char* i = chunk.begin;
    // see if there any interpolants
    const char* p = constant ? find_first_in_interval< exactly<hash_lbrace> >(i, chunk.end) :
                    find_first_in_interval< exactly<hash_lbrace>, block_comment >(i, chunk.end);

    if (!p) {
      String_Quoted_Ptr str_quoted = SASS_MEMORY_NEW(String_Quoted, pstate, std::string(i, chunk.end), 0, false, false, true, css);
      if (!constant && str_quoted->quote_mark()) str_quoted->quote_mark('*');
      return str_quoted;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1722,10 +1722,6 @@
 
     if (lex< variable >())
     { return SASS_MEMORY_NEW(Variable, pstate, Util::normalize_underscores(lexed)); }
-
-    // Special case handling for `%` proceeding an interpolant.
-    if (lex< sequence< exactly<'%'>, optional< percentage > > >())
-    { return SASS_MEMORY_NEW(String_Constant, pstate, lexed); }
 
     css_error("Invalid CSS", " after ", ": expected expression (e.g. 1px, bold), was ");
 
```
