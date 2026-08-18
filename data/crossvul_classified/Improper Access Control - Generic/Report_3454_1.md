# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3454_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3454_1`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1627-1667 of the vulnerable file.

	write_lock(&cifs_tcp_ses_lock);
	list_add(&tcp_ses->tcp_ses_list, &cifs_tcp_ses_list);
	write_unlock(&cifs_tcp_ses_lock);

	cifs_fscache_get_client_cookie(tcp_ses);

	return tcp_ses;

out_err:
	if (tcp_ses) {
		if (!IS_ERR(tcp_ses->hostname))
			kfree(tcp_ses->hostname);
		if (tcp_ses->ssocket)
			sock_release(tcp_ses->ssocket);
		kfree(tcp_ses);
	}
	return ERR_PTR(rc);
}

static struct cifsSesInfo *
cifs_find_smb_ses(struct TCP_Server_Info *server, char *username)
{
	struct list_head *tmp;
	struct cifsSesInfo *ses;

	write_lock(&cifs_tcp_ses_lock);
	list_for_each(tmp, &server->smb_ses_list) {
		ses = list_entry(tmp, struct cifsSesInfo, smb_ses_list);
		if (strncmp(ses->userName, username, MAX_USERNAME_SIZE))
			continue;

		++ses->ses_count;
		write_unlock(&cifs_tcp_ses_lock);
		return ses;
	}
	write_unlock(&cifs_tcp_ses_lock);
	return NULL;
}

static void
cifs_put_smb_ses(struct cifsSesInfo *ses)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1644,17 +1644,27 @@
 }
 
 static struct cifsSesInfo *
-cifs_find_smb_ses(struct TCP_Server_Info *server, char *username)
-{
-	struct list_head *tmp;
+cifs_find_smb_ses(struct TCP_Server_Info *server, struct smb_vol *vol)
+{
 	struct cifsSesInfo *ses;
 
 	write_lock(&cifs_tcp_ses_lock);
-	list_for_each(tmp, &server->smb_ses_list) {
-		ses = list_entry(tmp, struct cifsSesInfo, smb_ses_list);
-		if (strncmp(ses->userName, username, MAX_USERNAME_SIZE))
-			continue;
-
+	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
+		switch (server->secType) {
+		case Kerberos:
+			if (vol->linux_uid != ses->linux_uid)
+				continue;
+			break;
+		default:
+			/* anything else takes username/password */
+			if (strncmp(ses->userName, vol->username,
+				    MAX_USERNAME_SIZE))
+				continue;
+			if (strlen(vol->username) != 0 &&
+			    strncmp(ses->password, vol->password,
+				    MAX_PASSWORD_SIZE))
+				continue;
+		}
 		++ses->ses_count;
 		write_unlock(&cifs_tcp_ses_lock);
 		return ses;
@@ -1696,7 +1706,7 @@
 
 	xid = GetXid();
 
-	ses = cifs_find_smb_ses(server, volume_info->username);
+	ses = cifs_find_smb_ses(server, volume_info);
 	if (ses) {
 		cFYI(1, "Existing smb sess found (status=%d)", ses->status);
 
```
