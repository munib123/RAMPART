# CrossVul Fix Pair: Improper Input Validation in python
**Pair ID:** 1232_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1232_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```python
Lines 27-67 of the vulnerable file.

# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
###

from __future__ import division

import re
import math
import cmath
import types
import string

import supybot.utils as utils
from supybot.commands import *
import supybot.utils.minisix as minisix
import supybot.callbacks as callbacks
from supybot.i18n import PluginInternationalization, internationalizeDocstring
_ = PluginInternationalization('Math')

from .local import convertcore

baseArg = ('int', 'base', lambda i: i <= 36)

class Math(callbacks.Plugin):
    """Provides commands to work with math, such as a calculator and
    a unit converter."""
    @internationalizeDocstring
    def base(self, irc, msg, args, frm, to, number):
        """<fromBase> [<toBase>] <number>

        Converts <number> from base <fromBase> to base <toBase>.
        If <toBase> is left out, it converts to decimal.
        """
        if not number:
            number = str(to)
            to = 10
        try:
            irc.reply(self._convertBaseToBase(number, to, frm))
        except ValueError:
            irc.error(_('Invalid <number> for base %s: %s') % (frm, number))
    base = wrap(base, [('int', 'base', lambda i: 2 <= i <= 36),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,6 +44,7 @@
 _ = PluginInternationalization('Math')
 
 from .local import convertcore
+from .evaluator import safe_eval, InvalidNode, SAFE_ENV
 
 baseArg = ('int', 'base', lambda i: i <= 36)
 
@@ -97,36 +98,6 @@
             return str(number)
         return self._convertDecimalToBase(number, toBase)
 
-    _mathEnv = {'__builtins__': types.ModuleType('__builtins__'), 'i': 1j}
-    _mathEnv.update(math.__dict__)
-    _mathEnv.update(cmath.__dict__)
-    def _sqrt(x):
-        if isinstance(x, complex) or x < 0:
-            return cmath.sqrt(x)
-        else:
-            return math.sqrt(x)
-    def _cbrt(x):
-        return math.pow(x, 1.0/3)
-    def _factorial(x):
-        if x<=10000:
-            return float(math.factorial(x))
-        else:
-            raise Exception('factorial argument too large')
-    _mathEnv['sqrt'] = _sqrt
-    _mathEnv['cbrt'] = _cbrt
-    _mathEnv['abs'] = abs
-    _mathEnv['max'] = max
-    _mathEnv['min'] = min
-    _mathEnv['round'] = lambda x, y=0: round(x, int(y))
-    _mathSafeEnv = dict([(x,y) for x,y in _mathEnv.items()])
-    _mathSafeEnv['factorial'] = _factorial
-    _mathRe = re.compile(r'((?:(?<![A-Fa-f\d)])-)?'
-                         r'(?:0x[A-Fa-f\d]+|'
-                         r'0[0-7]+|'
-                         r'\d+\.\d+|'
-                         r'\.\d+|'
-                         r'\d+\.|'
-                         r'\d+))')
     def _floatToString(self, x):
         if -1e-10 < x < 1e-10:
             return '0'
@@ -157,17 +128,6 @@
         else:
             return '%s%s' % (realS, imagS)
 
-    _calc_match_forbidden_chars = re.compile('[_\[\]]')
-    _calc_remover = utils.str.MultipleRemover('_[] \t')
-    ###
-    # So this is how the 'calc' command works:
-    # First, we make a nice little safe environment for evaluation; basically,
-    # the names in the 'math' and 'cmath' modules.  Then, we remove the ability
-    # of a random user to get ints evaluated: this means we have to turn all
-    # int literals (even octal numbers and hexadecimal numbers) into floats.
-    # Then we delete all square brackets, underscores, and whitespace, so no
-    # one can do list comprehensions or call __...__ functions.
-    ###
     @internationalizeDocstring
     def calc(self, irc, msg, args, text):
         """<math expression>
@@ -179,56 +139,16 @@
         is that large values such as '10**24' might not be exact.
         """
         try:
-            text = str(text)
-        except UnicodeEncodeError:
-            irc.error(_("There's no reason you should have fancy non-ASCII "
-                            "characters in your mathematical expression. "
-                            "Please remove them."))
-            return
-        if self._calc_match_forbidden_chars.match(text):
-            # Note: this is important to keep this to forbid usage of
-            # __builtins__
-            irc.error(_('There\'s really no reason why you should have '
-                           'underscores or brackets in your mathematical '
-                           'expression.  Please remove them.'))
-            return
-        text = self._calc_remover(text)
-        if 'lambda' in text:
-            irc.error(_('You can\'t use lambda in this command.'))
-            return
-        text = text.lower()
-        def handleMatch(m):
-            s = m.group(1)
-            if s.startswith('0x'):
-                i = int(s, 16)
-            elif s.startswith('0') and '.' not in s:
-                try:
-                    i = int(s, 8)
-                except ValueError:
-                    i = int(s)
-            else:
-                i = float(s)
-            x = complex(i)
-            if x.imag == 0:
-                x = x.real
-                # Need to use string-formatting here instead of str() because
-                # use of str() on large numbers loses information:
-                # str(float(33333333333333)) => '3.33333333333e+13'
-                # float('3.33333333333e+13') => 33333333333300.0
-                return '%.16f' % x
-            return str(x)
-        text = self._mathRe.sub(handleMatch, text)
-        try:
             self.log.info('evaluating %q from %s', text, msg.prefix)
-            x = complex(eval(text, self._mathSafeEnv, self._mathSafeEnv))
+            x = complex(safe_eval(text, allow_ints=False))
             irc.reply(self._complexToString(x))
         except OverflowError:
             maxFloat = math.ldexp(0.9999999999999999, 1024)
             irc.error(_('The answer exceeded %s or so.') % maxFloat)
-        except TypeError:
-            irc.error(_('Something in there wasn\'t a valid number.'))
+        except InvalidNode as e:
+            irc.error(_('Invalid syntax: %s') % e.args[0])
         except NameError as e:
-            irc.error(_('%s is not a defined function.') % str(e).split()[1])
+            irc.error(_('%s is not a defined function.') % e.args[0])
         except Exception as e:
             irc.error(str(e))
     calc = wrap(calc, ['text'])
@@ -241,28 +161,15 @@
         math, and can thus cause the bot to suck up CPU.  Hence it requires
         the 'trusted' capability to use.
         """
-        if self._calc_match_forbidden_chars.match(text):
-            # Note: this is important to keep this to forbid usage of
-            # __builtins__
-            irc.error(_('There\'s really no reason why you should have '
-                           'underscores or brackets in your mathematical '
-                           'expression.  Please remove them.'))
-            return
-        # This removes spaces, too, but we'll leave the removal of _[] for
-        # safety's sake.
-        text = self._calc_remover(text)
-        if 'lambda' in text:
-            irc.error(_('You can\'t use lambda in this command.'))
-            return
-        text = text.replace('lambda', '')
         try:
             self.log.info('evaluating %q from %s', text, msg.prefix)
-            irc.reply(str(eval(text, self._mathEnv, self._mathEnv)))
+            x = safe_eval(text, allow_ints=True)
+            irc.reply(str(x))
         except OverflowError:
             maxFloat = math.ldexp(0.9999999999999999, 1024)
             irc.error(_('The answer exceeded %s or so.') % maxFloat)
-        except TypeError:
-            irc.error(_('Something in there wasn\'t a valid number.'))
+        except InvalidNode as e:
+            irc.error(_('Invalid syntax: %s') % e.args[0])
         except NameError as e:
             irc.error(_('%s is not a defined function.') % str(e).split()[1])
         except Exception as e:
@@ -286,8 +193,8 @@
                     x = abs(x)
                 stack.append(x)
             except ValueError: # Not a float.
-                if arg in self._mathSafeEnv:
-                    f = self._mathSafeEnv[arg]
+                if arg in SAFE_ENV:
+                    f = SAFE_ENV[arg]
                     if callable(f):
                         called = False
                         arguments = []
@@ -310,7 +217,7 @@
                     arg1 = stack.pop()
                     s = '%s%s%s' % (arg1, arg, arg2)
                     try:
-                        stack.append(eval(s, self._mathSafeEnv, self._mathSafeEnv))
+                        stack.append(safe_eval(s, allow_ints=False))
                     except SyntaxError:
                         irc.error(format(_('%q is not a defined function.'),
                                          arg))
```
