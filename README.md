# cas-secure

Secure Express/connect APIs against a CAS server

## Install

```bash
npm install --save cas-secure
```

## How to use

1. ### Require package
    ```javascript
    var secure = require('cas-secure').set(options);
    ```

    Where _options_ is one of the following:

    * __String__: The base url of _CAS_ (For example: _http://my.cas-server.com/cas_).
    * __Object__: An object with the following properties:
    * **base_ur** [Mandaory]: The base url of _CAS_ (For example: _http://my.cas-server.com/cas_).
    * **version** [Optional]: _CAS_ protocol version. Posible values are 1, 2 or 3. _Default 3_.
    * **action** [Optional]: Default action that **cas_secure** should take with failed authentication (_Default block_):
        * **block**: Returns a _401 (Unauthorized)_ status code.
        * **pass**: Pass the error to _next_, to be handled by *express/connect* error handler.
        * **ignore**: call _next_ middleware, but don't write info about user.
    * **validateUrl** [Optional]: Url for proxy/ticket validation:
        * Default for protocol version 1: _/validate_
        * Default for protocol version 2: _/proxyValidate_
        * Default for protocol version 3: _/p3/proxyValidate_
    * **service** [Optional]: this service identification. Defaults to the value of the Host header.

1. ### Use middleware

    ```javascript
    app.use(secure.validate(action), function SecuredMiddleware(req, res, next){
        /* 
        Your code goes here
        If user got authenticated:
            * req.cas.user will have user id
            * req.cas.attributes will have user attributes released by cas.
        */
    })
    ```
    _action_ can be one of _block_, _pass_ or _ignore_, and will override the configured default action.

    If no action is provided, will use the default one.


