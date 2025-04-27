# Configuring Authentik for Navidrome #

Here is a quick run-down on how to configure things in Authentik to
authenticate and provision Navidrome users.

We assume you have already installed Authentik in your Kubernetes
cluster.

It is reasonably straightforward:

 * Install Navidrome using the helm chart of your choice -
   e.g. https://truecharts.org/charts/stable/navidrome/ - make sure
   you configure an ingress so you can access it (we will remove that
   later)

 * Set up an admin user in Navidrome. This can be any name, but since
   we're using Authentik, `akadmin` is a good choice. Best to avoid
   "real" users you intend to provision.

 * Reconfigure navidrome:

   * Remove the ingress (you will no longer need it)

   * Configure Navidrome to trust a HTTP header for specifying a
     username by setting the `ND_REVERSEPROXYUSERHEADER` environment
     variable. Since we are using Authentik, we can use the header
     which Authentik uses by default: `X-Authentik-Username`.

   * Configure an IP whitelist for Navidrome (the
     `ND_REVERSEPROXYWHITELIST` environment variable) listing the
     network IP ranges for which the above HTTP header will be
     trusted. Since we removed the ingress, Navidrome will only be
     accessible from inside the Kubernetes cluster, so we can use
     `0.0.0.0/0` meaning "everything IPv4" (if you use IPv6, adjust
     accordingly)

 * In Authentik: Create the app. Nothing complicated.

 * In Authentik: Create a provider of type "Proxy", and configure the
   relevant external/internal URLS - e.g.:

        external URL: https://music.example.com/
	    internal URL: http://navidrome.NAMESPACE.svc.cluster.local:4533

   The idea is to get Authentik to proxy requests from the external
   URL directly to the service (inside the cluster) installed by the
   navidrome helm chart.

 * In Authentik: Edit the `authentik Embedded Outpost`: Make sure that
   your newly created provider is amongst the selected applications.

   While you are there: Examine the "Advanced Settings" for the
   Outpost: If they are correct, then Authentik will automatically
   create the necessary Ingress & Certificate resources in kubernetes.

   And if you have external-dns and cert-manager installed (and
   configured), everything will "just work".

 * Install the navidrome-scim-provider (the one you're reading about
   here); configure it with:

        navidrome:
          baseUrl: http://navidrome.home.svc.cluster.local:4533
          usernameHeader: X-Authentik-Username
          username: akadmin

   (adjust if you have decided to use different values in the previous
   steps)

   These tell the SCIM provider how to reach Navidrome.

   When installing the SCIM provider, the `helm install` output will
   tell you how to configure your identity provider. We will need that
   later.

 * In authentik: Create a SCIM provider. Configure it with

   * The URL for the SCIM provider (which you got from the previous
     step) - something similar to
     `http://navidrome-scim.home.svc.cluster.local:5000/scim/v2`

   * The bearer token extracted from the kubernetes secret created by
     `navidrome-scim`

 * In Authentik: Edit the app, and make the newly created SCIM
   provider a "backchannel provider" for your app

 * Let your users enjoy the music!
