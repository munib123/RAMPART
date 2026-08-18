# CrossVul Fix Pair: Improper Input Validation in php
**Pair ID:** 5369_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** php
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5369_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```php
Lines 267-326 of the vulnerable file.

				// Logout is set to default. Get the home page ItemID
				$lang_code = $app->input->cookie->getString(JApplicationHelper::getHash('language'));
				$item      = $app->getMenu()->getDefault($lang_code);
				$itemid    = $item->id;

				// Redirect to Home page after logout
				$url = 'index.php?Itemid=' . $itemid;
			}
		}
		else
		{
			// URL to redirect after logout, default page if no ItemID is set
			$url = $itemid ? 'index.php?Itemid=' . $itemid : JUri::root();
		}

		// Logout and redirect
		$this->setRedirect('index.php?option=com_users&task=user.logout&' . JSession::getFormToken() . '=1&return=' . base64_encode($url));
	}

	/**
	 * Method to register a user.
	 *
	 * @return  boolean
	 *
	 * @since   1.6
	 */
	public function register()
	{
		JSession::checkToken('post') or jexit(JText::_('JINVALID_TOKEN'));

		// Get the application
		$app = JFactory::getApplication();

		// Get the form data.
		$data = $this->input->post->get('user', array(), 'array');

		// Get the model and validate the data.
		$model  = $this->getModel('Registration', 'UsersModel');

		$form = $model->getForm();

		if (!$form)
		{
			JError::raiseError(500, $model->getError());

			return false;
		}

		$return = $model->validate($form, $data);

		// Check for errors.
		if ($return === false)
		{
			// Get the validation messages.
			$errors = $model->getErrors();

			// Push up to three validation messages out to the user.
			for ($i = 0, $n = count($errors); $i < $n && $i < 3; $i++)
			{
				if ($errors[$i] instanceof Exception)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -284,87 +284,6 @@
 	}
 
 	/**
-	 * Method to register a user.
-	 *
-	 * @return  boolean
-	 *
-	 * @since   1.6
-	 */
-	public function register()
-	{
-		JSession::checkToken('post') or jexit(JText::_('JINVALID_TOKEN'));
-
-		// Get the application
-		$app = JFactory::getApplication();
-
-		// Get the form data.
-		$data = $this->input->post->get('user', array(), 'array');
-
-		// Get the model and validate the data.
-		$model  = $this->getModel('Registration', 'UsersModel');
-
-		$form = $model->getForm();
-
-		if (!$form)
-		{
-			JError::raiseError(500, $model->getError());
-
-			return false;
-		}
-
-		$return = $model->validate($form, $data);
-
-		// Check for errors.
-		if ($return === false)
-		{
-			// Get the validation messages.
-			$errors = $model->getErrors();
-
-			// Push up to three validation messages out to the user.
-			for ($i = 0, $n = count($errors); $i < $n && $i < 3; $i++)
-			{
-				if ($errors[$i] instanceof Exception)
-				{
-					$app->enqueueMessage($errors[$i]->getMessage(), 'notice');
-
-					continue;
-				}
-
-				$app->enqueueMessage($errors[$i], 'notice');
-			}
-
-			// Save the data in the session.
-			$app->setUserState('users.registration.form.data', $data);
-
-			// Redirect back to the registration form.
-			$this->setRedirect('index.php?option=com_users&view=registration');
-
-			return false;
-		}
-
-		// Finish the registration.
-		$return = $model->register($data);
-
-		// Check for errors.
-		if ($return === false)
-		{
-			// Save the data in the session.
-			$app->setUserState('users.registration.form.data', $data);
-
-			// Redirect back to the registration form.
-			$message = JText::sprintf('COM_USERS_REGISTRATION_SAVE_FAILED', $model->getError());
-			$this->setRedirect('index.php?option=com_users&view=registration', $message, 'error');
-
-			return false;
-		}
-
-		// Flush the data from the session.
-		$app->setUserState('users.registration.form.data', null);
-
-		return true;
-	}
-
-	/**
 	 * Method to login a user.
 	 *
 	 * @return  boolean
```
