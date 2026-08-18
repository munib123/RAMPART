# CrossVul Fix Pair: Use of a One-Way Hash without a Salt in java
**Pair ID:** 1902_3
**Vulnerability Class:** Use of a One-Way Hash without a Salt
**CWE:** CWE-759
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1902_3`)

## Vulnerability Information & PoC

## Description
Use of a One-Way Hash without a Salt - This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables.

## Vulnerable Code
```java
Lines 1-29 of the vulnerable file.

package com.bijay.onlinevotingsystem.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.bijay.onlinevotingsystem.dto.Admin;
import com.bijay.onlinevotingsystem.util.DbUtil;

public class AdminDaoImpl implements AdminDao {

	PreparedStatement ps = null;

	@Override
	public void saveAdminInfo(Admin admin) {
		String sql = "insert into admin_table(admin_name, password) values(?,?)";
		try {
			ps = DbUtil.getConnection().prepareStatement(sql);
			ps.setString(1, admin.getAdminName());
			ps.setString(2, admin.getPassword());
			ps.executeUpdate();
		} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,6 +6,9 @@
 import java.util.ArrayList;
 import java.util.List;
 
+import javax.crypto.Cipher;
+
+import com.bijay.onlinevotingsystem.controller.SHA256;
 import com.bijay.onlinevotingsystem.dto.Admin;
 import com.bijay.onlinevotingsystem.util.DbUtil;
 
@@ -98,14 +101,14 @@
 	@Override
 	public boolean loginValidate(String userName, String password) {
 
-		String sql = "select * from admin_table where admin_name=? and password=?";
+		String sql = "select * from admin_table where admin_name=?";
 		try {
 			ps=DbUtil.getConnection().prepareStatement(sql);
 			ps.setString(1, userName);
-			ps.setString(2,password);
 			ResultSet rs =ps.executeQuery();
 			if (rs.next()) {
-				return true;
+				String cipherText = rs.getString("password");
+				return SHA256.validatePassword(password, cipherText);
 			}
 		} catch (SQLException | ClassNotFoundException e) {
 			e.printStackTrace();
```
