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
  namespace: grafana
spec:
  clusterProvider: keycloak
  clientName: grafana
  clientID: grafana
  redirects:
    - https://grafana.example.com/*
  secretName: grafana-oidc # will have values for id, secret, and issuerURL
  secretTemplate: # Clients can also add key/value pairs whose values will be templated (see example below)
    example.json: |
      {
        "secret": "{{ .ClientSecret }}",
        "id": "{{ .ClientID }}",
        "issuer": "{{ .IssuerURL }}"
      }
---
# An example grafana deployment that uses the above-configured client
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: grafana
  spec:
  replicas: 1
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana
        env:
          # you'll also need all the GF_DATABASE_* properties, of course
          - name: GRAFANA_SSL_MODE
            value: verify-full
          - name: GF_AUTH_GENERIC_OAUTH_ENABLED
            value: "true"
          - name: GF_AUTH_GENERIC_OAUTH_SCOPES
            value: "email profile"
          - name: GF_AUTH_GENERIC_OAUTH_CLIENT_ID
            valueFrom:
              secretKeyRef:
                name: grafana-oidc
                key: id
          - name: GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET
            valueFrom:
              secretKeyRef:
                name: grafana-oidc
                key: secret
          - name: OIDC_BASE
            valueFrom:
              secretKeyRef:
                name: grafana-oidc
                key: issuerURL
          - name: GF_AUTH_GENERIC_OAUTH_AUTH_URL
            value: "$(OIDC_BASE)/protocol/openid-connect/auth"
          - name: GF_AUTH_GENERIC_OAUTH_TOKEN_URL
            value: "$(OIDC_BASE)/protocol/openid-connect/token"
          - name: GF_AUTH_GENERIC_OAUTH_API_URL
            value: "$(OIDC_BASE)/protocol/openid-connect/userinfo"
          - name: GF_SERVER_ROOT_URL
            value: https://grafana.astuart.co
        ports:
        - containerPort: 3000
```
