# SCIM for Navidrome #

This provides SCIM support for Navidrome - i.e. it allows an Identity
Provider to manage users in Navidrom using the SCIM protocol.

It is intended for use in this scenario:

 * Navidrome is installed behind a proxy which authenticates users and
   injects a header in the HTTP requests reaching Navidrome.
   
 * Navidrome is configured to trust the username in the HTTP header -
   e.g. by setting the `ND_REVERSEPROXYUSERHEADER` and
   `ND_REVERSEPROXYWHITELIST` environment variables.
   
   This implies that Navidrome should not be accessible _without_
   going through the proxy as this would allow users to chose any
   identity.
   
   ... Except for this SCIM provider: It needs to access navidrome
   _directly_ and will inject its own HTTP header to authenticate.

Which basically translates to having navidrome-scim installed in the
same Kubernetes namespace as navidrome - this allows the SCIM provider
to access the navidrome service directly, bypassing the identity
provider.

This has been developed for (and tested with) Authentik; it _should_
work with other identity providers.

The users created in Navidrome will not have admin permissions, and
will have a random string as a password; the identity provider is not
expected to reveal the user's actual password.
