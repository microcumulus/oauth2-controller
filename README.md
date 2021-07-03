# OAuth2 Controller

The primary purpose of the OAuth2 Controller is to make it significantly easier
to manage OAuth2 clients and instances of the oauth2-proxy in kubernetes.
This controller provides CRDs and the ability to watch ingresses and services
for annotations, which will be dynamically replaced with instances of the
oauth2-proxy with the given configuration.
