# Architecture for the oauth2-controller

1. Providers and ClusterProviders give ways of creating oauth2 clients
1. There is a package prov for getting an implementation of ClientCreator with
   the different Specs.
1. The controller for client loads up the ClientCreator for the provider as
   specified in the Client CustomResource.
   1. It then creates the oauth client, places the secrets, and updates the
      status.
1. The controller for an OAuthProxy creates a Client Custom Resource, creates
   the deployment and service for the proxy, and then either updates or creates
   ingresses to use the proxy.

## Handling changes

1. To ensure that secrets stay around appropriately (when mounted as env, the
   consuming pods won't be able to observe updates) we add an annotation to the
   secret indicating the IDP ID that the secret was created from. If that still
   matches, we will not update secrets.
   1. Probably want to handle cred rotation as an explicit policy/action.
