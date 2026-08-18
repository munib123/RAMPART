# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in php
**Pair ID:** 2991_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2991_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```php
Lines 2521-2561 of the vulnerable file.

    			$text = $tmp.$langs->transnoentities("InvoiceAvoirAsk") . ' ';
    			// $text.='<input type="text" value="">';
    			$text .= '<select class="flat valignmiddle" name="fac_avoir" id="fac_avoir"';
    			if (! $optionsav)
    				$text .= ' disabled';
    			$text .= '>';
    			if ($optionsav) {
    				$text .= '<option value="-1"></option>';
    				$text .= $optionsav;
    			} else {
    				$text .= '<option value="-1">' . $langs->trans("NoInvoiceToCorrect") . '</option>';
    			}
    			$text .= '</select>';
    			$desc = $form->textwithpicto($text, $langs->transnoentities("InvoiceAvoirDesc"), 1, 'help', '', 0, 3);
    			print $desc;

				print '<div id="credit_note_options" class="clearboth">';
				print '&nbsp;&nbsp;&nbsp; <input data-role="none" type="checkbox" name="invoiceAvoirWithLines" id="invoiceAvoirWithLines" value="1" onclick="$(\'#credit_note_options input[type=checkbox]\').not(this).prop(\'checked\', false);" '.(GETPOST('invoiceAvoirWithLines','int')>0 ? 'checked':'').' /> <label for="invoiceAvoirWithLines">'.$langs->trans('invoiceAvoirWithLines')."</label>";
				print '<br>&nbsp;&nbsp;&nbsp; <input data-role="none" type="checkbox" name="invoiceAvoirWithPaymentRestAmount" id="invoiceAvoirWithPaymentRestAmount" value="1" onclick="$(\'#credit_note_options input[type=checkbox]\').not(this).prop(\'checked\', false);" '.(GETPOST('invoiceAvoirWithPaymentRestAmount','int')>0 ? 'checked':'').' /> <label for="invoiceAvoirWithPaymentRestAmount">'.$langs->trans('invoiceAvoirWithPaymentRestAmount')."</label>";
				print '</div>';
				
    			print '</div></div>';
    		}
		}
		else
		{
			print '<div class="tagtr listofinvoicetype"><div class="tagtd listofinvoicetype">';
			if (empty($conf->global->INVOICE_CREDIT_NOTE_STANDALONE)) $tmp='<input type="radio" name="type" id="radio_creditnote" value="0" disabled> ';
			else $tmp='<input type="radio" name="type" id="radio_creditnote" value="2" > ';
			$text = $tmp.$langs->trans("InvoiceAvoir") . ' ';
			$text.= '('.$langs->trans("YouMustCreateInvoiceFromThird").') ';
			$desc = $form->textwithpicto($text, $langs->transnoentities("InvoiceAvoirDesc"), 1, 'help', '', 0, 3);
			print $desc;
			print '</div></div>' . "\n";
		}
	}

	// Template invoice
	print '<div class="tagtr listofinvoicetype"><div class="tagtd listofinvoicetype">';
	$tmp='<input type="radio" name="type" id="radio_template" value="0" disabled> ';
	$text = $tmp.$langs->trans("RepeatableInvoice") . ' ';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2538,7 +2538,7 @@
 				print '&nbsp;&nbsp;&nbsp; <input data-role="none" type="checkbox" name="invoiceAvoirWithLines" id="invoiceAvoirWithLines" value="1" onclick="$(\'#credit_note_options input[type=checkbox]\').not(this).prop(\'checked\', false);" '.(GETPOST('invoiceAvoirWithLines','int')>0 ? 'checked':'').' /> <label for="invoiceAvoirWithLines">'.$langs->trans('invoiceAvoirWithLines')."</label>";
 				print '<br>&nbsp;&nbsp;&nbsp; <input data-role="none" type="checkbox" name="invoiceAvoirWithPaymentRestAmount" id="invoiceAvoirWithPaymentRestAmount" value="1" onclick="$(\'#credit_note_options input[type=checkbox]\').not(this).prop(\'checked\', false);" '.(GETPOST('invoiceAvoirWithPaymentRestAmount','int')>0 ? 'checked':'').' /> <label for="invoiceAvoirWithPaymentRestAmount">'.$langs->trans('invoiceAvoirWithPaymentRestAmount')."</label>";
 				print '</div>';
-				
+
     			print '</div></div>';
     		}
 		}
```
