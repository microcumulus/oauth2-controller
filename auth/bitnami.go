package auth

import (
	"context"
	"fmt"

	"github.com/Nerzal/gocloak/v8"
	"github.com/opentracing/opentracing-go"
	"k8s.io/client-go/kubernetes"
)

type BitnamiHelmKCCreator struct {
	Kube          kubernetes.Interface
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	IngressPrefix string `json:"ingressPrefix"`
	Realm         string `json:"realm"`
}

func (bh *BitnamiHelmKCCreator) CreateOIDCClient(ctx context.Context, c *gocloak.Client) (*OIDCClient, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "BitnamiHelmKCCreator.CreateOIDCClient")
	defer sp.Finish()

	cli, jwt, host, err := GetGoCloakClient(ctx, bh.Kube, bh.Namespace, bh.Name, bh.IngressPrefix)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	cl, err := cli.GetClients(ctx, jwt.AccessToken, "master", gocloak.GetClientsParams{
		ClientID: c.ClientID,
	})
	if err == nil && len(cl) == 1 {
		cred, err := cli.GetClientSecret(ctx, jwt.AccessToken, "master", *cl[0].ID)
		if err != nil {
			return nil, fmt.Errorf("couldn't get client secret: %w", err)
		}
		if cred.Value != nil && *cred.Value != "" {
			return &OIDCClient{
				IssuerURL:    host,
				ClientID:     *cl[0].ID,
				ClientSecret: *cred.Value,
			}, nil
		}
	}

	id, err := cli.CreateClient(ctx, jwt.AccessToken, bh.Realm, *c)
	if err != nil {
		return nil, fmt.Errorf("couldn't create client: %w", err)
	}

	cred, err := cli.RegenerateClientSecret(ctx, jwt.AccessToken, bh.Realm, id)
	if err != nil {
		return nil, fmt.Errorf("error regenerating secret: %w", err)
	}

	if cred.Value == nil {
		return nil, fmt.Errorf("regenerated secret had a nil value somehow: %v", cred)
	}

	return &OIDCClient{
		IssuerURL:    host,
		ClientID:     *cl[0].ID,
		ClientSecret: *cred.Value,
	}, nil
}

var _ OIDCCreator = &BitnamiHelmKCCreator{}
