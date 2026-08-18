# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 319_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `319_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 127-167 of the vulnerable file.

    while (is_space(peek(s)))
        if (next(s) == '\n')
            return TOK_END_OF_LINE;

    /* Skip comments. */
    if (chr(s, '#')) {
        skip_to_eol(s);
        goto skip_more_whitespace_and_comments;
    }

    /* See if we're done. */
    if (eof(s)) return TOK_END_OF_FILE;

    /* New token. */
    s->token_line = s->line;
    s->token_column = s->column;
    s->buf_pos = 0;

    /* LHS Keysym. */
    if (chr(s, '<')) {
        while (peek(s) != '>' && !eol(s))
            buf_append(s, next(s));
        if (!chr(s, '>')) {
            scanner_err(s, "unterminated keysym literal");
            return TOK_ERROR;
        }
        if (!buf_append(s, '\0')) {
            scanner_err(s, "keysym literal is too long");
            return TOK_ERROR;
        }
        val->string.str = s->buf;
        val->string.len = s->buf_pos;
        return TOK_LHS_KEYSYM;
    }

    /* Colon. */
    if (chr(s, ':'))
        return TOK_COLON;
    if (chr(s, '!'))
        return TOK_BANG;
    if (chr(s, '~'))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -144,7 +144,7 @@
 
     /* LHS Keysym. */
     if (chr(s, '<')) {
-        while (peek(s) != '>' && !eol(s))
+        while (peek(s) != '>' && !eol(s) && !eof(s))
             buf_append(s, next(s));
         if (!chr(s, '>')) {
             scanner_err(s, "unterminated keysym literal");
```
