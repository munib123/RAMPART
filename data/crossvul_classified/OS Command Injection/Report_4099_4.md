# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 4099_4
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4099_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 131-171 of the vulnerable file.

R_API int r_str_delta(char *p, char a, char b);
R_API void r_str_filter(char *str, int len);
R_API const char * r_str_tok(const char *str1, const char b, size_t len);
R_API wchar_t *r_str_mb_to_wc(const char *buf);
R_API char *r_str_wc_to_mb(const wchar_t *buf);
R_API wchar_t *r_str_mb_to_wc_l(const char *buf, int len);
R_API char *r_str_wc_to_mb_l(const wchar_t *buf, int len);
R_API const char *r_str_str_xy(const char *s, const char *word, const char *prev, int *x, int *y);

typedef void(*str_operation)(char *c);

R_API int r_str_do_until_token(str_operation op, char *str, const char tok);

R_API void r_str_reverse(char *str);
R_API int r_str_re_match(const char *str, const char *reg);
R_API int r_str_re_replace(const char *str, const char *reg, const char *sub);
R_API int r_str_path_unescape(char *path);
R_API char *r_str_path_escape(const char *path);
R_API int r_str_unescape(char *buf);
R_API char *r_str_escape(const char *buf);
R_API char *r_str_escape_dot(const char *buf);
R_API char *r_str_escape_latin1(const char *buf, bool show_asciidot, bool esc_bslash, bool colors);
R_API char *r_str_escape_utf8(const char *buf, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf8_keep_printable(const char *buf, bool show_asciidot, bool esc_bslash); // like escape_utf8 but leaves valid \uXXXX chars directly in utf-8
R_API char *r_str_escape_utf16le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf32le(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf16be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API char *r_str_escape_utf32be(const char *buf, int buf_size, bool show_asciidot, bool esc_bslash);
R_API void r_str_byte_escape(const char *p, char **dst, int dot_nl, bool default_dot, bool esc_bslash);
R_API char *r_str_format_msvc_argv(size_t argc, const char **argv);
R_API void r_str_uri_decode(char *buf);
R_API char *r_str_uri_encode(const char *buf);
R_API char *r_str_utf16_decode(const ut8 *s, int len);
R_API int r_str_utf16_to_utf8(ut8 *dst, int len_dst, const ut8 *src, int len_src, int little_endian);
R_API char *r_str_utf16_encode(const char *s, int len);
R_API char *r_str_escape_utf8_for_json(const char *s, int len);
R_API char *r_str_home(const char *str);
R_API char *r_str_r2_prefix(const char *str);
R_API size_t r_str_nlen(const char *s, int n);
R_API size_t r_str_nlen_w(const char *s, int n);
R_API size_t r_wstr_clen(const char *s);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,6 +148,7 @@
 R_API char *r_str_path_escape(const char *path);
 R_API int r_str_unescape(char *buf);
 R_API char *r_str_escape(const char *buf);
+R_API char *r_str_escape_sh(const char *buf);
 R_API char *r_str_escape_dot(const char *buf);
 R_API char *r_str_escape_latin1(const char *buf, bool show_asciidot, bool esc_bslash, bool colors);
 R_API char *r_str_escape_utf8(const char *buf, bool show_asciidot, bool esc_bslash);
```
