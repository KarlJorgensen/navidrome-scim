# A (naive) SCIM provider for Navidrome #

Navidrome does not natively support SCIM. Or SAML for that matter.
But it *does* support being behind a proxy which is expected to inject
user-information headers into the HTTP requests which reach navidrome.

But those users cannot actually _access_ Navidrome unless Navidrome
recognises them as legitimate users (they get a login box instead at
which point they're stuck).

This implements a (rather basic) SCIM provider for Navidrome which
creates/updates/deletes Navidrome users in response to requests from
the identity provider of your choice.

## Limitations ##

The SCIM provider assumes that Navidrome is configured to _trust_ a
(configurable) username header in the incoming requests - which would
be the case if it is behind an authenticating proxy.  But the SCIM
provider needs to be able to access navidrome _directly_, as it needs
to inject its own header.

Users created in Navidrome will _not_ be admin users. However, a
user's admin status will not be modified by the SCIM provider.

# NOTE #

This was developed for version 0.55.2 of Navidrome; although it is
likely to work on later versions too, no guarantees can be
offered. Sorry.

This has been tested using Authentik 2025.2.4, and _should_ work with
other identity providers.
