# CrossVul Fix Pair: Use of a One-Way Hash without a Salt in java
**Pair ID:** 1902_4
**Vulnerability Class:** Use of a One-Way Hash without a Salt
**CWE:** CWE-759
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1902_4`)

## Vulnerability Information & PoC

## Description
Use of a One-Way Hash without a Salt - This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables.

## Vulnerable Code
```java
Lines 1-30 of the vulnerable file.

package com.bijay.onlinevotingsystem.dao;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.sql.Date;

import com.bijay.onlinevotingsystem.dto.Voter;
import com.bijay.onlinevotingsystem.util.DbUtil;

public class VoterDaoImpl implements VoterDao {

	PreparedStatement ps = null;

	@Override
	public void saveVoterInfo(Voter voter) {
		String sql = "insert into voter_table(voter_name, password, gender, state_no, district, email, dob, imageurl) values(?,?,?,?,?,?,?,?)";
		try {
			ps = DbUtil.getConnection().prepareStatement(sql);
			ps.setString(1, voter.getVoterName());
			ps.setString(2, voter.getPassword());
			ps.setString(3, voter.getGender());
			ps.setInt(4, voter.getStateNo());
			ps.setString(5, voter.getDistrictName());
			ps.setString(6, voter.getEmail());
			ps.setDate(7, new Date(voter.getDob().getTime()));
			ps.setString(8, voter.getImgUrl());
			ps.executeUpdate();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -7,6 +7,7 @@
 import java.util.List;
 import java.sql.Date;
 
+import com.bijay.onlinevotingsystem.controller.SHA256;
 import com.bijay.onlinevotingsystem.dto.Voter;
 import com.bijay.onlinevotingsystem.util.DbUtil;
 
@@ -80,15 +81,15 @@
 
 	@Override
 	public boolean loginValidate(String userName, String password, String email) {
-		String sql = "select * from voter_table where voter_name=? and password=? and email=?";
+		String sql = "select * from voter_table where voter_name=? and email=?";
 		try {
 			ps = DbUtil.getConnection().prepareStatement(sql);
 			ps.setString(1, userName);
-			ps.setString(2, password);
-			ps.setString(3, email);
+			ps.setString(2, email);
 			ResultSet rs = ps.executeQuery();
 			if (rs.next()) {
-				return true;
+				String cipherText = rs.getString("password");
+				return SHA256.validatePassword(password, cipherText);
 			}
 		} catch (ClassNotFoundException | SQLException e) {
 			e.printStackTrace();
```
