# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 2539_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2539_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 939-979 of the vulnerable file.

// 清除noteList导航
Note.clearNoteList = function() {
    Note.noteItemListO.html(""); // 清空
}

// 清空所有, 在转换notebook时使用
Note.clearAll = function() {
    // 当前的笔记清空掉
    Note.clearCurNoteId();

    Note.clearNoteInfo();
    Note.clearNoteList();
};

// render到编辑器
// render note
Note.renderNote = function(note) {
    if (!note) {
        return;
    }
    // title
    $("#noteTitle").val(note.Title);

    // 当前正在编辑的
    // tags
    Tag.input.setTags(note.Tags);
};

// render content
// 这一步很慢
Note.renderNoteContent = function(content, dontNeedSetReadonly, seq2) {
    if (seq2 && seq2 != Note.contentAjaxSeq) {
        return;
    }
    setEditorContent(content.Content, content.IsMarkdown, content.Preview, function() {
        if (seq2 && seq2 != Note.contentAjaxSeq) {
            return;
        }
        Note.setCurNoteId(content.NoteId);

        if (!dontNeedSetReadonly) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -956,8 +956,10 @@
     if (!note) {
         return;
     }
+    var title = note.Title || '';
+    title = title.replace(/&lt;/g, '<').replace(/&gt;/g, '>');
     // title
-    $("#noteTitle").val(note.Title);
+    $("#noteTitle").val(title);
 
     // 当前正在编辑的
     // tags
@@ -1997,7 +1999,7 @@
     me.starNotesO.html('');
     for (var i = 0; i < notes.length; ++i) {
         var note = notes[i];
-        var t = tt(me.starItemT, note.NoteId, note.Title || getMsg('Untitled'));
+        var t = tt(me.starItemT, note.NoteId, trimTitle(note.Title) || getMsg('Untitled'));
         me.starNotesO.append(t);
     }
 
```
