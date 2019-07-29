# GW

A Go Web application framework.  This folds reusable parts of our infrastructure at [Zepheira](https://zepheira.com/) into one common base.  It provides:

* LDAP account integration
* JSON Web Token middleware (using a [JWT library](https://github.com/dgrijalva/jwt-go) and a [JWT middleware library](https://github.com/auth0/go-jwt-middleware))
* Authentication middleware based on LDAP and JWT
* CORS middleware
* Settings interface to configure LDAP and JWT
* Centralized error handling
* Template convenience methods
* Database convenience methods

We try to keep the API as stable as possible.

## Usage

Add as an import.

```golang
import (
    "github.com/zepheira/gw"
)
```

### LDAP

Tested with OpenLDAP.  In our setup, we have:

* an administrators LDAP group that automatically gets admin access in every application, which configurable but generally assumed to exist
* a forgotten password reset LDAP user with sufficient authority to change user passwords
* a binding LDAP user
* the `ppolicy` overlay enabled, which can lock out users after password failures
* put the special case lock time `000001010000Z` set by `ADMIN_LOCKED_TIME` to use to distinguish password failures from intentional locks
* the `memberof` overlay to provide inferred user-group property values
* users in their own DN subtree, using `uid` for the identifier
* groups in their own DN subtree, using `cn` for the identifier

Review the `LDAPGroup` and `LDAPUser` structs for interacting with the provided methods.

### JWT

Review the libraries listed above.  Private and public RSA keys need to be generated and their file locations handed to the `SetupJWTMiddleware` method.

Tying into LDAP, the JWT claims made are `username` and `exp` for expiration date.

### CORS

The CORS settings allow for a list of domains (origins) to be passed in.  Any request either matching a listed origin exactly or being a subdomain of an origin will have the CORS HTTP headers added, only for OPTIONS, GET, and POST methods.

### Templates

Templates will be loaded from a specified directory.  They'll be put in a `map[string]*template.Template` where the string index is the relative path to the template file.  Only one level of subdirectories are read in.  Middleware is provided to map requests to templates.

Delimiters for template fields are replaced with `<<` and `>>` instead of the usual double curly brackets to avoid collisions with other templating systems (like AngularJS).

To facilitate testing, templates can be reloaded by sending the application SIGUSR1, i.e., `kill -SIGUSR1 <pid>`.

### Settings

In order to pass your configuration values into this library, write up an implementation of the `Settings` interface, which will allow the rest of the library to call `GetCORSOptions`, for instance, and utilize your provided list allowed origins.

### Database Convenience

These methods are Postgres-specific.

There is a `Migrate` method using the [migrate library](github.com/mattes/migrate) to handle automigrating on application startup.

The `QuerySetHelpder` method takes values, often from HTTP requests, and appends ordering and limiting clauses to queries (which should not contain those clauses in already).

## Testing

Run with 

```
% go test -v -cover .
```

The `views/` directory and its contents exist for testing purposes.

More tests could be written.  There isn't much in the way of testing LDAP; those methods have been exercised through real world usage but are difficult to check without an active LDAP server to test against.

## Releases

This framework is mirrored to GitHub from our private repository.  Only squashed commits for each tag are published.
