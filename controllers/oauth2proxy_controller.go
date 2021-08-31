/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/opentracing/opentracing-go"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	microcumulusv1beta1 "github.com/microcumulus/oauth2-controller/api/v1beta1"
)

// OAuth2ProxyReconciler reconciles a OAuth2Proxy object
type OAuth2ProxyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=microcumul.us,resources=oauth2proxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=microcumul.us,resources=oauth2proxies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;update;patch;create;delete;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;update;patch;create;delete;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;update;patch;create;delete;list;watch

func (r *OAuth2ProxyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// lg := r.Log.WithValues("oauth2proxy", req.NamespacedName)

	// your logic here
	sp, ctx := opentracing.StartSpanFromContext(ctx, "ReplaceWithOauth2Proxy")
	defer sp.Finish()

	var spec microcumulusv1beta1.OAuth2Proxy
	err := r.Get(ctx, req.NamespacedName, &spec)
	if err != nil {
		return ctrl.Result{}, err
	}

	// First, get ingresses and/or services
	var ing networkv1.Ingress
	err = r.Get(ctx, types.NamespacedName{Namespace: spec.Spec.Ingress.Namespace, Name: spec.Spec.Ingress.Name}, &ing)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error fetching ingress matching reference %s: %w", spec.Spec.Ingress.String(), err)
	}
	// var svcs corev1.ServiceList

	// switch {
	// case spec.Spec.IngressSelector != nil:
	// 	err = r.List(ctx, &ings, client.MatchingLabels(spec.Spec.IngressSelector.MatchLabels))
	// 	if err != nil {
	// 		return ctrl.Result{}, fmt.Errorf("error fetching ingresses matching labels: %w", err)
	// 	}
	// case spec.Spec.Ingress != nil:
	// 	ings.Items = []networkv1.Ingress{ing}
	// 	case spec.Spec.ServiceSelector != nil:
	// 		err = r.List(ctx, &svcs, client.MatchingLabels(spec.Spec.ServiceSelector.MatchLabels))
	// 		if err != nil {
	// 			return ctrl.Result{}, fmt.Errorf("error fetching ingresses matching labels: %w", err)
	// 		}
	// 	case spec.Spec.Service != nil:
	// 		var svc corev1.Service
	// 		err = r.Get(ctx, types.NamespacedName{Namespace: spec.Spec.Service.Namespace, Name: spec.Spec.Service.Name}, &svc)
	// 		if err != nil {
	// 			return ctrl.Result{}, fmt.Errorf("error fetching services matching reference %s: %w", spec.Spec.Service.String(), err)
	// 		}
	// 		svcs.Items = []corev1.Service{svc}
	// }

	// Check for oidc secrets values; create if not exist
	var sec corev1.Secret
	err = r.Get(ctx, req.NamespacedName, &sec)
	if err != nil {
		var uris []string
		for _, rule := range ing.Spec.Rules {
			uris = append(uris, fmt.Sprintf("https://%s/*", rule.Host))
		}
		if len(uris) == 0 {
			return ctrl.Result{}, fmt.Errorf("no URIs present in ingress")
		}

		err = r.Create(ctx, &microcumulusv1beta1.OAuth2Client{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name,
				Namespace: req.Namespace,
			},
			Spec: microcumulusv1beta1.OAuth2ClientSpec{
				ClusterProvider: spec.Spec.ClusterClientProvider,
				Provider:        spec.Spec.ClientProvider,
				SecretName:      req.Name,
				Redirects:       uris,
			},
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("no secret data present, and could not create OAuth2Client object")
		}
		// Now requeue so the secret is created
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 10 * time.Second,
		}, nil
	}

	rSec, err := getSecretVal(ctx, r.Client, spec.Spec.RedisPasswordRef.Namespace, spec.Spec.RedisPasswordRef.SecretKeySelector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error getting redis secret: %w", err)
	}

	err = replaceWithOauth2Proxy(ctx, r.Client, &ing, string(sec.Data["id"]), string(sec.Data["secret"]), string(sec.Data["issuerURL"]), spec.Spec.RedisHost, rSec)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error replacing ingress with proxy: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *OAuth2ProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&microcumulusv1beta1.OAuth2Proxy{}).
		Complete(r)
}

func replaceWithOauth2Proxy(ctx context.Context, cs client.Client, ing *networkv1.Ingress, id, sec, issuerURL, redisHost, redisSec string) error {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "replaceWithOauth2Proxy")
	defer sp.Finish()

	n := fmt.Sprintf("%s-oauth2-proxy", ing.Name)

	bs := make([]byte, 16)
	rand.Read(bs)

	be := ing.Spec.Rules[0].HTTP.Paths[0].Backend
	m := map[string]string{
		"UPSTREAM":        fmt.Sprintf("http://%s:%d", be.Service.Name, be.Service.Port.Number),
		"OIDC_ISSUER_URL": issuerURL,
		"CLIENT_ID":       n,
		"CLIENT_SECRET":   sec,
		"COOKIE_SECRET":   base64.StdEncoding.EncodeToString(bs),
		"REDIS_PASSWORD":  redisSec,
	}

	err := cs.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n,
			Namespace: ing.Namespace,
		},
		StringData: m,
	})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error creating secret: %w", err)
	}

	om := metav1.ObjectMeta{
		Name:      n,
		Namespace: ing.Namespace,
		Labels: map[string]string{
			"app": n,
		},
		Annotations: map[string]string{
			"microcumul.us/injectssl": "microcumulus-ca",
		},
	}

	var env []corev1.EnvVar
	for k := range m {
		env = append(env, corev1.EnvVar{
			Name: "OAUTH2_PROXY_" + k,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: n,
					},
					Key: k,
				},
			},
		})
	}

	probe := corev1.Probe{
		InitialDelaySeconds: 0,
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: "/ping",
				Port: intstr.FromInt(4180),
			},
		},
	}
	err = cs.Create(ctx, &appsv1.Deployment{
		ObjectMeta: om,
		Spec: appsv1.DeploymentSpec{
			Replicas: &one32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": n,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: om,
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  n,
						Image: "quay.io/oauth2-proxy/oauth2-proxy:latest",
						Args: []string{
							"--upstream=$(OAUTH2_PROXY_UPSTREAM)",
							"--provider=oidc",
							"--provider-display-name=Keycloak",
							"--http-address=0.0.0.0:4180",
							"--email-domain=*",
							"--session-store-type=redis",
							"--cookie-secure=true",
							"--redis-connection-url=redis://" + redisHost,
							`--banner=<img src="https://microcumul.us/images/logo/logo.svg" alt="microcumulus logo" />`,
							"--custom-sign-in-logo=-",
						},
						Env: env,
						Ports: []corev1.ContainerPort{{
							ContainerPort: 4180,
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
		return fmt.Errorf("error creating deployment: %w", err)
	}

	err = cs.Create(ctx, &corev1.Service{
		ObjectMeta: om,
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: om.Labels,
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolTCP,
				Name:       n,
				Port:       80,
				TargetPort: intstr.FromInt(4180),
			}},
		},
	})
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
						Number: 80,
					},
				},
			}
		}
	}

	err = cs.Update(ctx, updatedIng)
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error updating ingress: %w", err)
	}
	return nil
}

var one32 = int32(1)
