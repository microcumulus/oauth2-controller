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
