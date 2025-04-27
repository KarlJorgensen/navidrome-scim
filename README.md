# A (naive) SCIM provider for Navidrome #

The Problem: [Navidrome](https://www.navidrome.org/) has support for
being behind a proxy which authenticates users and injects a HTTP
header identifying the user in the (proxied) request to Navidrome.

Which is great. This allows administrators to enforce some sort of
central authentication on the proxy.

But... Navidrome will not allow access to users _it_ does not
recognize: The user _must_ exist in the Navidrome database.

This solves that problem.

This implements a (rather basic) SCIM provider for Navidrome which
creates/updates/deletes users in Navidrome in response to requests
from the identity provider of your choice.

# Limitations #

The SCIM provider assumes that Navidrome is configured to _trust_ a
(configurable) username header in the incoming requests - which should
be the case if it is behind an authenticating proxy.

Unlike end users, the SCIM provider needs to be able to access
navidrome _directly_, as it needs to inject its own header,
identifying itself as an admin user - which you must create in
Navidrome first.

Users created by the SCIM provider in Navidrome will _not_ be admin
users. However, a user's admin status will not be modified by the SCIM
provider.

# NOTE #

This was developed for version 0.55.2 of Navidrome; although it is
likely to work on later versions too, no guarantees can be
offered. Sorry.

This has been tested using Authentik 2025.2.4, and _should_ work with
other identity providers.

# Configuring Authentik #

For quick notes on how to configure Authentik for Navidrome with this
provider, see [Authentik.md](Authentik.md)
