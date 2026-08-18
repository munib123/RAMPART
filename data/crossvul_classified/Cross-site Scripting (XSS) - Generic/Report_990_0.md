# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in php
**Pair ID:** 990_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `990_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```php
Lines 107-147 of the vulnerable file.

                return redirect(route('accounts.show', [$account->id]));
            }
        }
        // @codeCoverageIgnoreStart
        session()->flash('error', (string)trans('firefly.cannot_redirect_to_account'));

        return redirect(route('index'));
        // @codeCoverageIgnoreEnd
    }

    /**
     * @param Account $account
     *
     * @return RedirectResponse|\Illuminate\Routing\Redirector
     */
    protected function redirectToOriginalAccount(Account $account)
    {
        /** @var Transaction $transaction */
        $transaction = $account->transactions()->first();
        if (null === $transaction) {
            app('session')->flash('error', trans('firefly.account_missing_transaction', ['name' => $account->name, 'id' => $account->id]));
            Log::error(sprintf('Expected a transaction. Account #%d has none. BEEP, error.', $account->id));

            return redirect(route('index'));
        }

        $journal = $transaction->transactionJournal;
        /** @var Transaction $opposingTransaction */
        $opposingTransaction = $journal->transactions()->where('transactions.id', '!=', $transaction->id)->first();

        if (null === $opposingTransaction) {
            app('session')->flash('error', trans('firefly.account_missing_transaction', ['name' => $account->name, 'id' => $account->id]));
            Log::error(sprintf('Expected an opposing transaction. Account #%d has none. BEEP, error.', $account->id));
        }

        return redirect(route('accounts.show', [$opposingTransaction->account_id]));
    }

    /**
     * Remember previous URL.
     *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,7 +124,7 @@
         /** @var Transaction $transaction */
         $transaction = $account->transactions()->first();
         if (null === $transaction) {
-            app('session')->flash('error', trans('firefly.account_missing_transaction', ['name' => $account->name, 'id' => $account->id]));
+            app('session')->flash('error', trans('firefly.account_missing_transaction', ['name' => e($account->name), 'id' => $account->id]));
             Log::error(sprintf('Expected a transaction. Account #%d has none. BEEP, error.', $account->id));
 
             return redirect(route('index'));
@@ -135,7 +135,7 @@
         $opposingTransaction = $journal->transactions()->where('transactions.id', '!=', $transaction->id)->first();
 
         if (null === $opposingTransaction) {
-            app('session')->flash('error', trans('firefly.account_missing_transaction', ['name' => $account->name, 'id' => $account->id]));
+            app('session')->flash('error', trans('firefly.account_missing_transaction', ['name' => e($account->name), 'id' => $account->id]));
             Log::error(sprintf('Expected an opposing transaction. Account #%d has none. BEEP, error.', $account->id));
         }
 
```
