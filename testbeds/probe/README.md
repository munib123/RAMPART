# probe - one function per locator-rule fix

A minimal target where each function is constructed so that exactly ONE of the eight P2
correctness fixes to `rules/locators.sc` changes its outcome. shopfast cannot show these (it has
no decorators, no `abort(404)`, no docstring that happens to contain "lock"), so on shopfast every
fix is a no-op by construction and only proves non-regression. Here each fix has a number.

| file | function | fix | before | after |
|---|---|---|---|---|
| views_authn.py | order_detail | 2 AUTHN/AUTHZ split | suppressed by `login_required` | IDOR fires; login is evidence, not a guard |
| views_docstring.py | reserve_stock | 3 docstring out of guard blob | suppressed by "lock" in the docstring | TOCTOU fires |
| views_abort.py | invoice_detail | 5 `abort(401/403` not `abort(` | suppressed by `abort(404)` | IDOR fires |
| views_allowlist.py | update_settings | 6 drop `" in ["` from ALLOWLIST | suppressed by an unrelated `if x in [...]` | mass assignment fires |
| views_allowlist.py | update_settings_safe | 6 (must stay quiet) | quiet (`ALLOWED_FIELDS`) | still quiet |
| views_decorator.py | get_note | 7 match `(name)` not substring | suppressed: `get_note_extra = check_owner(get_note_extra)` contains "get_note" | IDOR fires |
| views_decorator.py | get_note_extra | 7 (must stay quiet) | quiet (decorated with check_owner) | still quiet |

Flask-flavoured so it shares vocabulary with shopfast. Not runnable; a static target only.
