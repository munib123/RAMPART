# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in php
**Pair ID:** 2054_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2054_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```php
Lines 71-111 of the vulnerable file.

				<tr'.$warna.'>
					<td style="text-align: center;">'.$no.'</td>
					<td class="left"><a href="article-'.$data['seftitle'].'.html" title="'.$data['title'].'">'.$data['title'].'</a></td>
				</tr>';
				$no++;					
			}
			$tengah .= '
			</tbody>
		</table>
		</div>';
		$tengah .= $a-> getPaging($jumlah, $pg, $stg);
	}
	
	
	if($_GET['action'] == 'search'){
		
		$tengah .= '
		<h2>Pencarian Berita</h2>
		<div class="border" style="text-align:center;"><img src="mod/content/images/banner_searching_data.gif" alt="Searching Data" /></div>';
		
		$search	= !isset($_GET['search']) ? cleanText($_POST['search']) : cleanText($_GET['search']);
		
		if(!$search){
			$tengah .= '<div class="error">Maaf Anda Belum Memasukkan Kata Pencarian</div>';
		}else{
		
			$query 	= $db->sql_query("SELECT * FROM `mod_content` WHERE `type`='news' AND (`title` LIKE '%$search%' OR `content` LIKE '%$search%' OR `caption` LIKE '%$search%' OR `tags` LIKE '%$search%') ORDER BY `date` DESC");
			$jumlah = $db->sql_numrows($query);
			$limit 	= 15;
			
			if($jumlah>0){
				$tengah .= '<div class="sukses">Ditemukan : <b>'.$jumlah.'</b> data dengan Kata Kunci : <i><b>'.$search.'</b></i></div>';
			}else{
				$tengah .= '<div class="error">Maaf Data yang Anda cari tidak di temukan</div>';
			}
					
			$a 		= new paging_s ($limit,'search-'.$search,'.html');
	
			if(isset($offset)){
				$no = $offset + 1;
			}else{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,7 @@
 		<h2>Pencarian Berita</h2>
 		<div class="border" style="text-align:center;"><img src="mod/content/images/banner_searching_data.gif" alt="Searching Data" /></div>';
 		
-		$search	= !isset($_GET['search']) ? cleanText($_POST['search']) : cleanText($_GET['search']);
+		$search	= !isset($_GET['search']) ? mysqli_real_escape_string(cleanText($_POST['search'])) : mysqli_real_escape_string(cleanText($_GET['search']));
 		
 		if(!$search){
 			$tengah .= '<div class="error">Maaf Anda Belum Memasukkan Kata Pencarian</div>';
```
