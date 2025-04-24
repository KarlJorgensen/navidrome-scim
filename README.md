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


## NOTE ##

This does not use the Navidrome API - it accesses the underlying
Navidrome database directly, and will thus be sensitive to any
schema/logic changes in Navidrome.

This was developed for version 0.55.2 of Navidrome; although it is
likely to work on later versions too, no guarantees can be
offered. Sorry.

This has been tested using Authentik 2025.2.4.
