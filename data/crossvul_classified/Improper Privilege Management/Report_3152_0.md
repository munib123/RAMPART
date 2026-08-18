# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3152_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3152_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 429-469 of the vulnerable file.

int arp_check(const char *dev, uint32_t destaddr, uint32_t srcaddr);
// assign an IP address using arp scanning
uint32_t arp_assign(const char *dev, Bridge *br);
// scan interface (--scan option)
void arp_scan(const char *dev, uint32_t srcaddr, uint32_t srcmask);

// veth.c
int net_create_veth(const char *dev, const char *nsdev, unsigned pid);
int net_create_macvlan(const char *dev, const char *parent, unsigned pid);
int net_move_interface(const char *dev, unsigned pid);

// util.c
void drop_privs(int nogroups);
int mkpath_as_root(const char* path);
void extract_command_name(int index, char **argv);
void logsignal(int s);
void logmsg(const char *msg);
void logargs(int argc, char **argv) ;
void logerr(const char *msg);
int copy_file(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode);
int is_dir(const char *fname);
int is_link(const char *fname);
char *line_remove_spaces(const char *buf);
char *split_comma(char *str);
int not_unsigned(const char *str);
int find_child(pid_t parent, pid_t *child);
void check_private_dir(void);
void update_map(char *mapping, char *map_file);
void wait_for_other(int fd);
void notify_other(int fd);
char *expand_home(const char *path, const char* homedir);
const char *gnu_basename(const char *path);
uid_t pid_get_uid(pid_t pid);
void invalid_filename(const char *fname);
uid_t get_group_id(const char *group);
int remove_directory(const char *path);
void flush_stdin(void);
int set_perms(const char *fname, uid_t uid, gid_t gid, mode_t mode);

// fs_var.c
void fs_var_log(void);	// mounting /var/log
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -446,6 +446,8 @@
 void logargs(int argc, char **argv) ;
 void logerr(const char *msg);
 int copy_file(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode);
+void copy_file_as_user(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode);
+void touch_file_as_user(const char *fname, uid_t uid, gid_t gid, mode_t mode);
 int is_dir(const char *fname);
 int is_link(const char *fname);
 char *line_remove_spaces(const char *buf);
```
