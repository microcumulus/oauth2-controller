package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v8"
	"github.com/opentracing/opentracing-go"
)

func getKeycloakIngress(ctx context.Context, cs IngressLister, ingPrefix string) (string, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "getKeycloakIngress")
	defer sp.Finish()

	ings, err := cs.ListIngresses(ctx, "keycloak")
	if err != nil {
		return "", fmt.Errorf("couldn't list ingresses: %w", err)
	}
	var host string
	for _, ing := range ings.Items {
		for _, rule := range ing.Spec.Rules {
			if strings.HasPrefix(rule.Host, ingPrefix) {
				host = rule.Host
			}
		}
	}
	if host == "" {
		return "", fmt.Errorf("found no ingress with expected hostname keycloak.*")
	}
	return fmt.Sprintf("https://%s/", host), nil
}

// GetGoCloakClient can return a gocloak "client" (gocloak.GoCloak) based on
// the keycloak installation provided by the bitnami keycloak
func GetGoCloakClient(ctx context.Context, cs SecureStackCreator, ns, chartName, ingPrefix string) (gocloak.GoCloak, *gocloak.JWT, string, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "GetGoCloakClient")
	defer sp.Finish()

	sec, err := cs.GetSecret(ctx, ns, fmt.Sprintf("%s-keycloak", chartName))
	if err != nil {
		return nil, nil, "", fmt.Errorf("couldn't get admin secret: %w", err)
	}

	pass := string(sec.Data["admin-password"])
	host, err := getKeycloakIngress(ctx, cs, ingPrefix)
	if err != nil {
		return nil, nil, "", fmt.Errorf("no public host found for client")
	}

	cli := gocloak.NewClient(host)
	jwt, err := cli.LoginAdmin(ctx, "user", pass, "master")
	if err != nil {
		return nil, nil, "", fmt.Errorf("couldn't login: %w", err)
	}
	return cli, jwt, host, nil
}
