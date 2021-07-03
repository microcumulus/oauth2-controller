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
	"k8s.io/client-go/kubernetes"
)

const (
	proxPort = 4180
	httpPort = 80
)

// OIDCClient represents the critical data to be able to connect with an openid
// connect client that supports the discovery endpoints.
type OIDCClient struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
}

// An OIDCCreator can takes a context and client spec, and returns a clientid and
// clientsecret or error.
type OIDCCreator interface {
	CreateOIDCClient(ctx context.Context, c gocloak.Client) (*OIDCClient, error)
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

// ReplaceWithOauth2Proxy replaces an ingress with the oauth2 proxy
func ReplaceWithOauth2Proxy(ctx context.Context, cs kubernetes.Interface, ing *networkv1.Ingress, oid OIDCCreator, opts ProxyOpts) error {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "ReplaceWithOauth2Proxy")
	defer sp.Finish()

	c, err := getGocloakSpecForIngress(ctx, ing)
	if err != nil {
		return fmt.Errorf("could't build client spec: %w", err)
	}

	oClient, err := oid.CreateOIDCClient(ctx, *c)
	if err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	om := metav1.ObjectMeta{
		Name:      *c.Name,
		Namespace: ing.Namespace,
		Labels: map[string]string{
			"app": *c.Name,
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

	env, err := opts.SetupEnv(ctx, cs, ing, oClient, c)
	if err != nil {
		return fmt.Errorf("error speccing out proxy env vars: %w", err)
	}

	args, err := opts.Args(ctx)
	if err != nil {
		return fmt.Errorf("error getting args from proxyopts: %w", err)
	}

	_, err = cs.AppsV1().Deployments(ing.Namespace).Create(ctx, &appsv1.Deployment{
		ObjectMeta: om,
		Spec: appsv1.DeploymentSpec{
			Replicas: &one32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": *c.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: om,
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  *c.Name,
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
	}, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error creating deployment: %w", err)
	}

	_, err = cs.CoreV1().Services(ing.Namespace).Create(ctx, &corev1.Service{
		ObjectMeta: om,
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: om.Labels,
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolTCP,
				Name:       *c.Name,
				Port:       httpPort,
				TargetPort: intstr.FromInt(proxPort),
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error creating oidc service: %w", err)
	}

	updatedIng := ing.DeepCopy()

	for i := range updatedIng.Spec.Rules {
		for j := range updatedIng.Spec.Rules[i].HTTP.Paths {
			updatedIng.Spec.Rules[i].HTTP.Paths[j].Backend = networkv1.IngressBackend{
				Service: &networkv1.IngressServiceBackend{
					Name: om.Name,
					Port: networkv1.ServiceBackendPort{
						Number: httpPort,
					},
				},
			}
		}
	}

	_, err = cs.NetworkingV1().Ingresses(ing.Namespace).Update(ctx, updatedIng, metav1.UpdateOptions{})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error updating ingress: %w", err)
	}
	return nil
}

var one32 = int32(1)
