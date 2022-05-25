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
	"encoding/json"
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

const (
	annotPreviousRules  = "microcumul.us/previous-rules"
	finalizerStringProx = "microcumul.us/proxy-controller"
)

// OAuth2ProxyReconciler reconciles a OAuth2Proxy object
type OAuth2ProxyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func (r *OAuth2ProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&microcumulusv1beta1.OAuth2Proxy{}).
		Complete(r)
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
		if strings.Contains(err.Error(), "not found") {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// First, get ingresses and/or services
	var ing networkv1.Ingress
	err = r.Get(ctx, types.NamespacedName{Namespace: spec.Spec.Ingress.Namespace, Name: spec.Spec.Ingress.Name}, &ing)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error fetching ingress matching reference %s: %w", spec.Spec.Ingress.String(), err)
	}

	// If the object has been deleted
	if !spec.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.handleDelete(ctx, spec, ing)
	}

	if !containsString(spec.Finalizers, finalizerStringProx) {
		withFinal := spec.DeepCopy()
		withFinal.Finalizers = append(withFinal.Finalizers, finalizerStringProx)
		err = r.Update(ctx, withFinal)
		return ctrl.Result{Requeue: true}, err
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
		if len(ing.Spec.Rules) > 0 {
			uris = append(uris, fmt.Sprintf("https://%s/", ing.Spec.Rules[0].Host))
		}
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
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: spec.APIVersion,
					Kind:       spec.Kind,
					Name:       spec.Name,
					UID:        spec.UID,
				}},
			},
			Spec: microcumulusv1beta1.OAuth2ClientSpec{
				ClusterProvider: spec.Spec.ClusterClientProvider,
				Provider:        spec.Spec.ClientProvider,
				ClientID:        spec.Name,
				ClientName:      spec.Name,
				SecretName:      req.Name,
				Redirects:       uris,
			},
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("no secret data present, and could not create OAuth2Client object: %w", err)
		}
		// Now requeue so the secret is created
		return ctrl.Result{
			Requeue:      true,
			RequeueAfter: 10 * time.Second,
		}, nil
	}

	rSec, err := getSecretVal(ctx, r.Client, spec.Spec.SessionStore.Redis.PasswordRef.Namespace, spec.Spec.SessionStore.Redis.PasswordRef.SecretKeySelector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error getting redis secret: %w", err)
	}

	groupClaim, err := r.getGroupClaim(ctx, spec)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("couldn't get jwt group claim key from provider: %w", err)
	}

	err = replaceWithOauth2Proxy(ctx, r.Client, &ing, spec, oa2ProxyOpts{
		id:         string(sec.Data["id"]),
		secret:     string(sec.Data["secret"]),
		issuerURL:  string(sec.Data["issuerURL"]),
		redisHost:  spec.Spec.SessionStore.Redis.Host,
		redisPass:  rSec,
		groupClaim: groupClaim,
		groups:     spec.Spec.AllowedGroups,
		optsMap:    spec.Spec.ProxyOpts,
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error replacing ingress with proxy: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *OAuth2ProxyReconciler) getGroupClaim(ctx context.Context, spec microcumulusv1beta1.OAuth2Proxy) (string, error) {
	return "groups", nil
}

func (r *OAuth2ProxyReconciler) handleDelete(ctx context.Context, spec microcumulusv1beta1.OAuth2Proxy, ing networkv1.Ingress) (ctrl.Result, error) {
	if !containsString(spec.Finalizers, finalizerStringProx) { // Success case; nothing left to do
		return ctrl.Result{}, nil
	}

	if ing.Annotations[annotPreviousRules] != "" {
		revertedIng := ing.DeepCopy()
		var oldRules []networkv1.IngressRule
		err := json.Unmarshal([]byte(ing.Annotations[annotPreviousRules]), &oldRules)
		if err != nil {
			return ctrl.Result{Requeue: false}, fmt.Errorf("error unmarshaling annotation to revert ingress rules: %w", err)
		}
		revertedIng.Spec.Rules = oldRules
		delete(revertedIng.Annotations, annotPreviousRules)
		err = r.Update(ctx, revertedIng)
		if err != nil {
			return ctrl.Result{Requeue: false}, fmt.Errorf("error reverting ingress: %w", err)
		}
	}

	repl := spec.DeepCopy()
	repl.Finalizers = removeString(repl.Finalizers, finalizerStringProx)

	err := r.Update(ctx, repl)
	if err != nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("error removing finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

type oa2ProxyOpts struct {
	id         string
	secret     string
	issuerURL  string
	redisHost  string
	redisPass  string
	groupClaim string
	groups     []string
	optsMap    map[string]string
}

func replaceWithOauth2Proxy(ctx context.Context, cs client.Client, ing *networkv1.Ingress, spec microcumulusv1beta1.OAuth2Proxy, opts oa2ProxyOpts) error {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "replaceWithOauth2Proxy")
	defer sp.Finish()

	bs := make([]byte, 16)
	rand.Read(bs)

	updatedIng := ing.DeepCopy()

	if ing.Annotations[annotPreviousRules] == "" {
		oldRules, _ := json.Marshal(ing.Spec.Rules)
		updatedIng.Annotations[annotPreviousRules] = string(oldRules)
	} else {
		// If there are old rules already, make sure we use those for the rest of the setup
		err := json.Unmarshal([]byte(ing.Annotations[annotPreviousRules]), &updatedIng.Spec.Rules)
		if err != nil {
			return fmt.Errorf("error grabbing old rules: %w", err)
		}
	}

	for i, rule := range updatedIng.Spec.Rules {
		be := rule.HTTP.Paths[0].Backend
		m := map[string]string{
			"UPSTREAM":        fmt.Sprintf("http://%s:%d", be.Service.Name, be.Service.Port.Number),
			"OIDC_ISSUER_URL": opts.issuerURL,
			"CLIENT_ID":       opts.id,
			"CLIENT_SECRET":   opts.secret,
			"COOKIE_SECRET":   base64.StdEncoding.EncodeToString(bs),
		}
		if opts.redisPass != "" {
			m["REDIS_PASSWORD"] = opts.redisPass
		}
		if opts.groupClaim != "" {
			m["OIDC_GROUPS_CLAIM"] = opts.groupClaim
		}
		if opts.groups != nil {
			m["ALLOWED_GROUPS"] = strings.Join(opts.groups, ",")
			m["SCOPE"] = "offline_access openid profile roles email"
		}

		// TODO smart merging?
		for k, v := range opts.optsMap {
			m[k] = v
		}

		proxName := fmt.Sprintf("oauth2-proxy-%s-%s", opts.id, be.Service.Name)

		err := cs.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      proxName,
				Namespace: ing.Namespace,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: spec.APIVersion,
					Kind:       spec.Kind,
					Name:       spec.Name,
					UID:        spec.UID,
				}},
			},
			StringData: m,
		})
		if err != nil && !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("error creating secret: %w", err)
		}

		om := metav1.ObjectMeta{
			Name:      proxName,
			Namespace: ing.Namespace,
			Labels: map[string]string{
				"app":  opts.id,
				"tier": "proxy",
			},
			// Annotations: map[string]string{
			// 	"microcumul.us/injectssl": "microcumulus-ca", // TODO: remove
			// },
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: spec.APIVersion,
				Kind:       spec.Kind,
				Name:       spec.Name,
				UID:        spec.UID,
			}},
		}

		var env []corev1.EnvVar
		for k := range m {
			env = append(env, corev1.EnvVar{
				Name: "OAUTH2_PROXY_" + k,
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: proxName,
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
						"app": opts.id,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: om,
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{
							Name:  opts.id,
							Image: "quay.io/oauth2-proxy/oauth2-proxy:latest",
							Args: []string{
								"--upstream=$(OAUTH2_PROXY_UPSTREAM)",
								"--provider=oidc",
								"--provider-display-name=Keycloak",
								"--http-address=0.0.0.0:4180",
								"--email-domain=*",
								"--session-store-type=redis",
								"--cookie-secure=true",
								"--redis-connection-url=redis://" + opts.redisHost,
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
					Name:       proxName,
					Port:       80,
					TargetPort: intstr.FromInt(4180),
				}},
			},
		})
		if err != nil && !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("error creating oidc service: %w", err)
		}

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

	err := cs.Update(ctx, updatedIng)
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return fmt.Errorf("error updating ingress: %w", err)
	}
	return nil
}

var one32 = int32(1)
