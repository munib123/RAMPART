# CrossVul Fix Pair: Origin Validation Error in cpp
**Pair ID:** 3128_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3128_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```cpp
Lines 871-911 of the vulnerable file.

// JT_PushMessage
//----------------------------------------------------------------------------
JT_PushMessage::JT_PushMessage(Task *parent)
:Task(parent)
{
}

JT_PushMessage::~JT_PushMessage()
{
}

bool JT_PushMessage::take(const QDomElement &e)
{
	if(e.tagName() != "message")
		return false;

	QDomElement e1 = e;
	QDomElement forward;
	Message::CarbonDir cd = Message::NoCarbon;

	// Check for Carbon
	QDomNodeList list = e1.childNodes();
	for (int i = 0; i < list.size(); ++i) {
		QDomElement el = list.at(i).toElement();

		if (el.attribute("xmlns") == QLatin1String("urn:xmpp:carbons:2") && (el.tagName() == QLatin1String("received") || el.tagName() == QLatin1String("sent"))) {
			QDomElement el1 = el.firstChildElement();
			if (el1.tagName() == QLatin1String("forwarded") && el1.attribute(QLatin1String("xmlns")) == QLatin1String("urn:xmpp:forward:0")) {
				QDomElement el2 = el1.firstChildElement(QLatin1String("message"));
				if (!el2.isNull()) {
					forward = el2;
					cd = el.tagName() == QLatin1String("received")? Message::Received : Message::Sent;
					break;
				}
			}
		}
		else if (el.tagName() == QLatin1String("forwarded") && el.attribute(QLatin1String("xmlns")) == QLatin1String("urn:xmpp:forward:0")) {
			forward = el.firstChildElement(QLatin1String("message")); // currently only messages are supportted
			// TODO <delay> element support
			if (!forward.isNull()) {
				break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -888,14 +888,18 @@
 	QDomElement forward;
 	Message::CarbonDir cd = Message::NoCarbon;
 
+	Jid fromJid = Jid(e1.attribute(QLatin1String("from")));
 	// Check for Carbon
 	QDomNodeList list = e1.childNodes();
 	for (int i = 0; i < list.size(); ++i) {
 		QDomElement el = list.at(i).toElement();
 
-		if (el.attribute("xmlns") == QLatin1String("urn:xmpp:carbons:2") && (el.tagName() == QLatin1String("received") || el.tagName() == QLatin1String("sent"))) {
+		if (el.attribute("xmlns") == QLatin1String("urn:xmpp:carbons:2")
+		    && (el.tagName() == QLatin1String("received") || el.tagName() == QLatin1String("sent"))
+		    && fromJid.compare(Jid(e1.attribute(QLatin1String("to"))), false)) {
 			QDomElement el1 = el.firstChildElement();
-			if (el1.tagName() == QLatin1String("forwarded") && el1.attribute(QLatin1String("xmlns")) == QLatin1String("urn:xmpp:forward:0")) {
+			if (el1.tagName() == QLatin1String("forwarded")
+			    && el1.attribute(QLatin1String("xmlns")) == QLatin1String("urn:xmpp:forward:0")) {
 				QDomElement el2 = el1.firstChildElement(QLatin1String("message"));
 				if (!el2.isNull()) {
 					forward = el2;
@@ -904,7 +908,8 @@
 				}
 			}
 		}
-		else if (el.tagName() == QLatin1String("forwarded") && el.attribute(QLatin1String("xmlns")) == QLatin1String("urn:xmpp:forward:0")) {
+		else if (el.tagName() == QLatin1String("forwarded")
+			 && el.attribute(QLatin1String("xmlns")) == QLatin1String("urn:xmpp:forward:0")) {
 			forward = el.firstChildElement(QLatin1String("message")); // currently only messages are supportted
 			// TODO <delay> element support
 			if (!forward.isNull()) {
@@ -913,7 +918,6 @@
 		}
 	}
 
-	QString from = e1.attribute(QLatin1String("from"));
 	Stanza s = client()->stream().createStanza(addCorrectNS(forward.isNull()? e1 : forward));
 	if(s.isNull()) {
 		//printf("take: bad stanza??\n");
@@ -926,7 +930,7 @@
 		return false;
 	}
 	if (!forward.isNull()) {
-		m.setForwardedFrom(Jid(from));
+		m.setForwardedFrom(fromJid);
 		m.setCarbonDirection(cd);
 	}
 
```
