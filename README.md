# OAuth2 Controller

The primary purpose of the OAuth2 Controller is to make it significantly easier
to manage OAuth2 clients and instances of the oauth2-proxy in kubernetes.
This controller provides CRDs and the ability to watch ingresses and services
for annotations, which will be dynamically replaced with instances of the
oauth2-proxy with the given configuration.

Currently, any ingress can be selected and will be replaced by an instance of
oauth2-proxy. The oauth2 client will be created as well, in the provided
keycloak instance (assuming that the admin password is available in a secret as
created by the
[bitnami/keycloak](https://github.com/bitnami/charts/tree/master/bitnami/keycloak/#installing-the-chart) helm chart).

Example:

```yaml
apiVersion: microcumul.us/v1beta1
kind: ClusterOAuth2ClientProvider
metadata:
  name: keycloak
spec:
  keycloak:
    baseURL: https://keycloak.example.com
    realm: master
    userAuth:
      username: user # The default set up by bitnami/keycloak
      passwordRef: # A secret ref to the admin password
        namespace: auth
        name: auth-keycloak
        key: admin-password
---
# A full on oauth2-proxy instance configured against the specified oauth2 provider
apiVersion: microcumul.us/v1beta1
kind: OAuth2Proxy
metadata:
  name: prom
  namespace: kube-system
spec:
  clusterClientProvider: keycloak
  # Currently redis is the only supported session backend for this controller; requires a host and password 
  sessionStore:
    redis:
      host: redis-master.default
      passwordRef: # An optional reference to a redis password stored in a variable
        namespace: default
        name: redis
        key: redis-password
  ingress:
    namespace: kube-system
    name: prometheus
---
# For clients who support direct integration, this can manage your oidc clients for you
apiVersion: microcumul.us/v1beta1
kind: OAuth2Client
metadata:
  name: grafana
  namespace: kube-system
spec:
  clusterProvider: keycloak
  clientName: grafana
  clientID: grafana
  secretName: grafana-oidc # will have values for id, secret, and issuerURL
  redirects:
    - https://grafana.example.com/*
```
