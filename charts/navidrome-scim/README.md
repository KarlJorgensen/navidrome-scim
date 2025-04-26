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
   
 * Navidrome uses a SQLite database - which is the default.
 
 * The PersistentVolumeClaim for navidrome's "data" volume (named
   `navidrome-data` by default) as AccessModes which include
   `ReadWriteMany`.

Navidrome's default `ND_DBPATH` should NOT be used in conjuction with
`navidrome-scim`: **THIS CAN CAUSE DATABASE CORRUPTION** as it assumes
a _shared_ cache.

Instead: Navidrome must be configured to use a _private_ cache,
e.g. by setting

    ND_DBPATH: /data/navidrome.db?cache=private&_busy_timeout=15000&_journal_mode=WAL&_foreign_keys=on&synchronous=normal

This has been developed for (and tested with) Authentik; it _should_
work with other identity providers.

The users created in Navidrome will not have admin permissions, and
will have a random string as a password; the identity provider is not
expected to reveal the user's actual password.
