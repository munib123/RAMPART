# CrossVul Fix Pair: Origin Validation Error in javascript
**Pair ID:** 2992_8
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2992_8`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```javascript
Lines 20-60 of the vulnerable file.


import AddressBar from './AddressBar';
import Store from './store';

import styles from './web.css';

@observer
export default class Web extends Component {
  static contextTypes = {
    api: PropTypes.object.isRequired
  }

  static propTypes = {
    params: PropTypes.object.isRequired
  }

  store = Store.get(this.context.api);

  componentDidMount () {
    this.store.gotoUrl(this.props.params.url);
    return this.store.generateToken();
  }

  componentWillReceiveProps (props) {
    this.store.gotoUrl(props.params.url);
  }

  render () {
    const { currentUrl, token } = this.store;

    if (!token) {
      return (
        <div className={ styles.wrapper }>
          <h1 className={ styles.loading }>
            <FormattedMessage
              id='web.requestToken'
              defaultMessage='Requesting access token...'
            />
          </h1>
        </div>
      );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,7 +37,6 @@
 
   componentDidMount () {
     this.store.gotoUrl(this.props.params.url);
-    return this.store.generateToken();
   }
 
   componentWillReceiveProps (props) {
```
