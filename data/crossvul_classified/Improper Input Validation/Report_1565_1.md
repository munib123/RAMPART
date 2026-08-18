# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1565_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1565_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 389-429 of the vulnerable file.

void xbind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen);
#define xlisten libreport_xlisten
void xlisten(int s, int backlog);
#define xsendto libreport_xsendto
ssize_t xsendto(int s, const void *buf, size_t len,
                const struct sockaddr *to, socklen_t tolen);

#define xstat libreport_xstat
void xstat(const char *name, struct stat *stat_buf);
#define fstat_st_size_or_die libreport_fstat_st_size_or_die
off_t fstat_st_size_or_die(int fd);
#define stat_st_size_or_die libreport_stat_st_size_or_die
off_t stat_st_size_or_die(const char *filename);

#define xopen3 libreport_xopen3
int xopen3(const char *pathname, int flags, int mode);
#define xopen libreport_xopen
int xopen(const char *pathname, int flags);
#define xunlink libreport_xunlink
void xunlink(const char *pathname);

/* Just testing dent->d_type == DT_REG is wrong: some filesystems
 * do not report the type, they report DT_UNKNOWN for every dirent
 * (and this is not a bug in filesystem, this is allowed by standards).
 * This function handles this case. Note: it returns 0 on symlinks
 * even if they point to regular files.
 */
#define is_regular_file libreport_is_regular_file
int is_regular_file(struct dirent *dent, const char *dirname);

#define dot_or_dotdot libreport_dot_or_dotdot
bool dot_or_dotdot(const char *filename);
#define last_char_is libreport_last_char_is
char *last_char_is(const char *s, int c);

#define string_to_bool libreport_string_to_bool
bool string_to_bool(const char *s);

#define xseteuid libreport_xseteuid
void xseteuid(uid_t euid);
#define xsetegid libreport_xsetegid
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -406,6 +406,8 @@
 int xopen(const char *pathname, int flags);
 #define xunlink libreport_xunlink
 void xunlink(const char *pathname);
+#define xunlinkat libreport_xunlinkat
+void xunlinkat(int dir_fd, const char *pathname, int flags);
 
 /* Just testing dent->d_type == DT_REG is wrong: some filesystems
  * do not report the type, they report DT_UNKNOWN for every dirent
@@ -415,6 +417,8 @@
  */
 #define is_regular_file libreport_is_regular_file
 int is_regular_file(struct dirent *dent, const char *dirname);
+#define is_regular_file_at libreport_is_regular_file_at
+int is_regular_file_at(struct dirent *dent, int dir_fd);
 
 #define dot_or_dotdot libreport_dot_or_dotdot
 bool dot_or_dotdot(const char *filename);
```
