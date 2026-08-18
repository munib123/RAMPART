# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 1777_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1777_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 545-586 of the vulnerable file.

            var pl = this.managedPlaylists[i];

            var isactive = ''
            if(pl.id == this.editingPlaylist){
                isactive = ' class="active" ';
            } else {
                isactive = ' class="playlist-tab-inactive" ';
            }
            pltabs += '<li '+isactive+' id="'+this.tabid2htmlid(pl.id)+'">';

            var isplaying = '';
            if(pl.id == this.playingPlaylist){
                isplaying += '&#9654;';
            }

            var isunsaved = '';
            if(!pl.saved && pl.reason_open !== 'queue'){
                isunsaved += ' <em>(unsaved)</em>';
            }


            pltabs += '<a href="#" onclick="playlistManager.showPlaylist('+pl.id+')">'+isplaying+' '+pl.name+ isunsaved;
            if(pl.closable){
                pltabs += '<span class="playlist-tab-closer pointer" href="#" onclick="playlistManager.closePlaylist('+pl.id+')">&times;</span>';
            }
            pltabs += '</a></li>';
        }
        pltabs += '<li class="playlist-tab-inactive playlist-tab-new"><a href="#" onclick="playlistManager.newPlaylist()"><b>+</b></a></li>';
        $(self.cssSelectorPlaylistChooser+' ul').empty()
        $(self.cssSelectorPlaylistChooser+' ul').append(pltabs);
    },
    tabid2htmlid : function(id){
        return this.plid2htmlid(id)+'-tab';
    },
    plid2htmlid : function(id){
        return 'pl-'+id;
    },
    htmlid2plid : function(htmlid){
        return parseInt(htmlid.slice(4,htmlid.length))
    },
    refreshPlaylists : function(){
        window.console.log('refreshPlaylists');
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -562,8 +562,9 @@
                 isunsaved += ' <em>(unsaved)</em>';
             }
 
-
-            pltabs += '<a href="#" onclick="playlistManager.showPlaylist('+pl.id+')">'+isplaying+' '+pl.name+ isunsaved;
+            // fix for CVE-2015-8310
+            var escaped_playlist_name = $("<div>").text(pl.name).html();
+            pltabs += '<a href="#" onclick="playlistManager.showPlaylist('+pl.id+')">'+isplaying+' '+escaped_playlist_name + isunsaved;
             if(pl.closable){
                 pltabs += '<span class="playlist-tab-closer pointer" href="#" onclick="playlistManager.closePlaylist('+pl.id+')">&times;</span>';
             }
```
