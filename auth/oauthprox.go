package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v8"
	"github.com/opentracing/opentracing-go"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	proxPort = 4180
	httpPort = 80
)

// OIDCClient represents the critical data to be able to connect with an openid
// connect client that supports the discovery endpoints.
type OIDCClient struct {
	IssuerURL string
	// Redirects    []string
	ClientID     string
	ClientSecret string
}

// An OIDCCreator can takes a context and client spec, and returns a clientid and
// clientsecret or error.
type OIDCCreator interface {
	CreateOIDCClient(ctx context.Context, c *gocloak.Client) (*OIDCClient, error)
}

// Returns a gocloak spec for a given kubernetes ingress spec
func getGocloakSpecForIngress(ctx context.Context, ing *networkv1.Ingress) (*gocloak.Client, error) {
	var uris []string
	for _, rule := range ing.Spec.Rules {
		uris = append(uris, fmt.Sprintf("https://%s/*", rule.Host))
	}
	if len(uris) == 0 {
		return nil, fmt.Errorf("no URIs present in ingress")
	}

	return &gocloak.Client{
		Name:                    gocloak.StringP(fmt.Sprintf("oauth2-" + ing.Name)),
		RedirectURIs:            &uris,
		BaseURL:                 &uris[0],
		ConsentRequired:         gocloak.BoolP(false),
		AdminURL:                &uris[0],
		Enabled:                 gocloak.BoolP(true),
		PublicClient:            gocloak.BoolP(false),
		ClientID:                gocloak.StringP(fmt.Sprintf("%s-oauth2-proxy", ing.Name)),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
	}, nil
}

// ReplaceWithOauth2Proxy replaces an ingress with the oauth2 proxy.
func ReplaceWithOauth2Proxy(ctx context.Context, cs SecureStackCreator, ing *networkv1.Ingress, oid OIDCCreator, opts ProxyOpts) error {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "ReplaceWithOauth2Proxy")
	defer sp.Finish()

	opts.Target.Ingress = ing

	c, err := getGocloakSpecForIngress(ctx, ing)
	if err != nil {
		return fmt.Errorf("could't build client spec: %w", err)
	}

	oClient, err := oid.CreateOIDCClient(ctx, c)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	svc, err := createSvc(ctx, cs, oClient, opts)

	updatedIng := ing.DeepCopy()

	for i := range updatedIng.Spec.Rules {
		for j := range updatedIng.Spec.Rules[i].HTTP.Paths {
			updatedIng.Spec.Rules[i].HTTP.Paths[j].Backend = networkv1.IngressBackend{
				Service: &networkv1.IngressServiceBackend{
					Name: svc.Name,
					Port: networkv1.ServiceBackendPort{
						Number: httpPort,
					},
				},
			}
		}
	}

	_, err = cs.CreateIngress(ctx, ing)
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error updating ingress: %w", err)
	}
	return nil
}

func createSvc(ctx context.Context, cs SecureStackCreator, oClient *OIDCClient, opts ProxyOpts) (*corev1.Service, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "createSvc")
	defer sp.Finish()

	ns, n := opts.targetSvcNamespaceAndName()
	proxN := n + "-oauth2-proxy"

	om := metav1.ObjectMeta{
		Name:      proxN,
		Namespace: ns,
		Labels: map[string]string{
			"app": proxN,
		},
		Annotations: opts.Annotations,
	}

	probe := corev1.Probe{
		InitialDelaySeconds: 0,
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/ping",
				Port: intstr.FromInt(proxPort),
			},
		},
	}

	env, err := opts.SetupEnv(ctx, cs, oClient)
	if err != nil {
		return nil, fmt.Errorf("error speccing out proxy env vars: %w", err)
	}

	args, err := opts.Args(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting args from proxyopts: %w", err)
	}

	_, err = cs.CreateDeployment(ctx, &appsv1.Deployment{
		ObjectMeta: om,
		Spec: appsv1.DeploymentSpec{
			Replicas: &one32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": proxN,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: om,
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  n,
						Image: "quay.io/oauth2-proxy/oauth2-proxy:latest",
						Args:  args,
						Env:   env,
						Ports: []corev1.ContainerPort{{
							ContainerPort: proxPort,
							Protocol:      corev1.ProtocolTCP,
						}},
						LivenessProbe:  &probe,
						ReadinessProbe: &probe,
					}},
				},
			},
		},
	})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return nil, fmt.Errorf("error creating deployment: %w", err)
	}

	svc, err := cs.CreateService(ctx, &corev1.Service{
		ObjectMeta: om,
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: om.Labels,
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolTCP,
				Name:       ns,
				Port:       httpPort,
				TargetPort: intstr.FromInt(proxPort),
			}},
		},
	})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return nil, fmt.Errorf("error creating oidc service: %w", err)
	}
	return svc, nil
}

var one32 = int32(1)
