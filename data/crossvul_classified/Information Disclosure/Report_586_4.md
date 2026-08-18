# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 586_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `586_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 186-232 of the vulnerable file.


        /**
         * @covers \yii\log\Dispatcher::dispatch()
         */
        public function testDispatchWithFakeTarget2ThrowExceptionWhenCollect()
        {
            static::$microtimeIsMocked = true;
            $target1 = $this->getMockBuilder('yii\\log\\Target')
                ->setMethods(['collect'])
                ->getMockForAbstractClass();

            $target2 = $this->getMockBuilder('yii\\log\\Target')
                ->setMethods(['collect'])
                ->getMockForAbstractClass();

            $target1->expects($this->exactly(2))
                ->method('collect')
                ->withConsecutive(
                    [$this->equalTo('messages'), $this->equalTo(true)],
                    [
                        [[
                            'Unable to send log via ' . get_class($target1) . ': Exception: some error',
                            Logger::LEVEL_WARNING,
                            'yii\log\Dispatcher::dispatch',
                            'time data',
                            [],
                        ]],
                        true,
                    ]
                );

            $target2->expects($this->once())
                ->method('collect')
                ->with(
                    $this->equalTo('messages'),
                    $this->equalTo(true)
                )->will($this->throwException(new UserException('some error')));

            $dispatcher = new Dispatcher(['targets' => ['fakeTarget1' => $target1, 'fakeTarget2' => $target2]]);

            static::$functions['microtime'] = function ($arguments) {
                $this->assertEquals([true], $arguments);
                return 'time data';
            };

            $dispatcher->dispatch('messages', true);
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -203,13 +203,33 @@
                 ->withConsecutive(
                     [$this->equalTo('messages'), $this->equalTo(true)],
                     [
-                        [[
-                            'Unable to send log via ' . get_class($target1) . ': Exception: some error',
-                            Logger::LEVEL_WARNING,
-                            'yii\log\Dispatcher::dispatch',
-                            'time data',
-                            [],
-                        ]],
+                        $this->callback(function($arg) use ($target1) {
+                            if (!isset($arg[0][0], $arg[0][1], $arg[0][2], $arg[0][3])) {
+                                return false;
+                            }
+
+                            if (strpos($arg[0][0], 'Unable to send log via ' . get_class($target1) . ': Exception (Exception) \'yii\base\UserException\' with message \'some error\'') !== 0) {
+                                return false;
+                            }
+
+                            if ($arg[0][1] !== Logger::LEVEL_WARNING) {
+                                return false;
+                            }
+
+                            if ($arg[0][2] !== 'yii\log\Dispatcher::dispatch') {
+                                return false;
+                            }
+
+                            if ($arg[0][3] !== 'time data') {
+                                return false;
+                            }
+
+                            if ($arg[0][4] !== []) {
+                                return false;
+                            }
+
+                            return true;
+                        }),
                         true,
                     ]
                 );
```
