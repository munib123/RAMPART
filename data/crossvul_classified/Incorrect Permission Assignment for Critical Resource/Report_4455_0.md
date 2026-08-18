# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in scala
**Pair ID:** 4455_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4455_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```scala
Lines 296-336 of the vulnerable file.

    pvo
  }

  def getPoll(pollId: String, polls: Polls): Option[PollVO] = {
    var pvo: Option[PollVO] = None
    polls.get(pollId) foreach (p => pvo = Some(p.toPollVO()))
    pvo
  }

  def showPollResult(pollId: String, polls: Polls) {
    polls.get(pollId) foreach {
      p =>
        p.showResult
        polls.currentPoll = Some(p)
    }
  }

  def respondToQuestion(pollId: String, questionID: Int, responseID: Int, responder: Responder, polls: Polls) {
    polls.polls.get(pollId) match {
      case Some(p) => {
        p.respondToQuestion(questionID, responseID, responder)
      }
      case None =>
    }
  }

}

object PollType {
  val YesNoPollType = "YN"
  val TrueFalsePollType = "TF"
  val CustomPollType = "CUSTOM"
  val LetterPollType = "A-"
  val NumberPollType = "1-"
}

object PollFactory {

  val LetterArray = Array("A", "B", "C", "D", "E", "F")
  val NumberArray = Array("1", "2", "3", "4", "5", "6")

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,7 +313,10 @@
   def respondToQuestion(pollId: String, questionID: Int, responseID: Int, responder: Responder, polls: Polls) {
     polls.polls.get(pollId) match {
       case Some(p) => {
-        p.respondToQuestion(questionID, responseID, responder)
+        if (!p._responders.exists(_ == responder)) {
+          p.addResponder(responder)
+          p.respondToQuestion(questionID, responseID, responder)
+        }
       }
       case None =>
     }
@@ -455,6 +458,11 @@
   private var _stopped: Boolean = false
   private var _showResult: Boolean = false
   private var _numResponders: Int = 0
+  var _responders = new ArrayBuffer[Responder]()
+
+  def addResponder(responder: Responder) {
+    _responders += (responder)
+  }
 
   def showingResult() { _showResult = true }
   def showResult(): Boolean = { _showResult }
```
