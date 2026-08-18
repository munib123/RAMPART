# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 5452_1
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5452_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 90-132 of the vulnerable file.

		$this->tree->expects($this->once())->method('getNodeForPath')->with('/files/welcome.txt')->willReturn(null);
		$result = $this->plugin->httpGet($this->request, $this->response);
		$this->assertTrue($result);
	}

	/**
	 * @dataProvider providesCardWithOrWithoutPhoto
	 * @param bool $expected
	 * @param array $getPhotoResult
	 */
	public function testCardWithOrWithoutPhoto($expected, $getPhotoResult) {
		$this->request->expects($this->once())->method('getQueryParameters')->willReturn(['photo' => true]);
		$this->request->expects($this->once())->method('getPath')->willReturn('/files/welcome.txt');

		$card = $this->getMockBuilder('Sabre\CardDAV\Card')->disableOriginalConstructor()->getMock();
		$this->tree->expects($this->once())->method('getNodeForPath')->with('/files/welcome.txt')->willReturn($card);

		$this->plugin->expects($this->once())->method('getPhoto')->willReturn($getPhotoResult);

		if (!$expected) {
			$this->response->expects($this->once())->method('setHeader');
			$this->response->expects($this->once())->method('setStatus');
			$this->response->expects($this->once())->method('setBody');
		}

		$result = $this->plugin->httpGet($this->request, $this->response);
		$this->assertEquals($expected, $result);
	}

	public function providesCardWithOrWithoutPhoto() {
		return [
			[true, null],
			[false, ['Content-Type' => 'image/jpeg', 'body' => '1234']],
		];
	}

	/**
	 * @dataProvider providesPhotoData
	 * @param $expected
	 * @param $cardData
	 */
	public function testGetPhoto($expected, $cardData) {
		/** @var Card | \PHPUnit_Framework_MockObject_MockObject $card */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -107,9 +107,20 @@
 		$this->plugin->expects($this->once())->method('getPhoto')->willReturn($getPhotoResult);
 
 		if (!$expected) {
-			$this->response->expects($this->once())->method('setHeader');
-			$this->response->expects($this->once())->method('setStatus');
-			$this->response->expects($this->once())->method('setBody');
+			$this->response
+				->expects($this->at(0))
+				->method('setHeader')
+				->with('Content-Type', $getPhotoResult['Content-Type']);
+			$this->response
+				->expects($this->at(1))
+				->method('setHeader')
+				->with('Content-Disposition', 'attachment');
+			$this->response
+				->expects($this->once())
+				->method('setStatus');
+			$this->response
+				->expects($this->once())
+				->method('setBody');
 		}
 
 		$result = $this->plugin->httpGet($this->request, $this->response);
@@ -142,12 +153,43 @@
 
 	public function providesPhotoData() {
 		return [
-			'empty vcard' => [false, ''],
-			'vcard without PHOTO' => [false, "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nEND:VCARD\r\n"],
-			'vcard 3 with PHOTO' => [['Content-Type' => 'image/jpeg', 'body' => '12345'], "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO;ENCODING=b;TYPE=JPEG:MTIzNDU=\r\nEND:VCARD\r\n"],
-			'vcard 3 with PHOTO URL' => [false, "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO;TYPE=JPEG;VALUE=URI:http://example.com/photo.jpg\r\nEND:VCARD\r\n"],
-			'vcard 4 with PHOTO' => [['Content-Type' => 'image/jpeg', 'body' => '12345'], "BEGIN:VCARD\r\nVERSION:4.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO:data:image/jpeg;base64,MTIzNDU=\r\nEND:VCARD\r\n"],
-			'vcard 4 with PHOTO URL' => [false, "BEGIN:VCARD\r\nVERSION:4.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO;MEDIATYPE=image/jpeg:http://example.org/photo.jpg\r\nEND:VCARD\r\n"],
+			'empty vcard' => [
+				false,
+				''
+			],
+			'vcard without PHOTO' => [
+				false,
+				"BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nEND:VCARD\r\n"
+			],
+			'vcard 3 with PHOTO' => [
+				[
+					'Content-Type' => 'image/jpeg',
+					'body' => '12345'
+				],
+				"BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO;ENCODING=b;TYPE=JPEG:MTIzNDU=\r\nEND:VCARD\r\n"
+			],
+			'vcard 3 with PHOTO URL' => [
+				false,
+				"BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO;TYPE=JPEG;VALUE=URI:http://example.com/photo.jpg\r\nEND:VCARD\r\n"
+			],
+			'vcard 4 with PHOTO' => [
+				[
+					'Content-Type' => 'image/jpeg',
+					'body' => '12345'
+				],
+				"BEGIN:VCARD\r\nVERSION:4.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO:data:image/jpeg;base64,MTIzNDU=\r\nEND:VCARD\r\n"
+			],
+			'vcard 4 with PHOTO URL' => [
+				false,
+				"BEGIN:VCARD\r\nVERSION:4.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO;MEDIATYPE=image/jpeg:http://example.org/photo.jpg\r\nEND:VCARD\r\n"
+			],
+			'vcard 4 with PHOTO AND INVALID MIMEtYPE' => [
+				[
+					'Content-Type' => 'application/octet-stream',
+					'body' => '12345'
+				],
+				"BEGIN:VCARD\r\nVERSION:4.0\r\nPRODID:-//Sabre//Sabre VObject 3.5.0//EN\r\nUID:12345\r\nFN:12345\r\nN:12345;;;;\r\nPHOTO:data:image/svg;base64,MTIzNDU=\r\nEND:VCARD\r\n"
+			],
 		];
 	}
 }
```
