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
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v8"
	"github.com/go-logr/logr"
	"github.com/opentracing/opentracing-go"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/microcumulus/oauth2-controller/api/v1beta1"
	microcumulusv1beta1 "github.com/microcumulus/oauth2-controller/api/v1beta1"
)

// OAuth2ClientReconciler reconciles a OAuth2Client object
type OAuth2ClientReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=microcumul.us.my.domain,resources=oauth2clients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=microcumul.us.my.domain,resources=oauth2clients/status,verbs=get;update;patch

func (r *OAuth2ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "OAuth2ClientReconciler.Reconcile")
	defer sp.Finish()
	defer func() {
		if err != nil {
			sp.SetTag("error", true)
			sp.LogKV("error", err)
		}
	}()
	// lg := r.Log.WithValues("oauth2client", req.NamespacedName)

	var c v1beta1.OAuth2Client
	err = r.Get(ctx, req.NamespacedName, &c)
	if err != nil {
		return ctrl.Result{
			Requeue: true,
			// RequeueAfter: 30 * time.Second,
		}, fmt.Errorf("couldn't get client body: %w", err)
	}

	var prov v1beta1.ClusterOAuth2ClientProvider
	err = r.Get(ctx, client.ObjectKey{
		Name:      c.Spec.Provider.Name,
		Namespace: "",
	}, &prov)
	if err != nil {
		return res, fmt.Errorf("error getting given clusterprovider %s: %w", c.Spec.Provider.Name, err)
	}

	// TODO: abstract this into a provider interface
	cloak := gocloak.NewClient(prov.Spec.Keycloak.BaseURL)
	var jwt *gocloak.JWT
	switch {
	case prov.Spec.Keycloak.UserAuth != nil:
		ua := prov.Spec.Keycloak.UserAuth

		pass, err := r.getSecretVal(ctx, c.Namespace, ua.Password)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in: %w", err)
		}

		jwt, err = cloak.LoginAdmin(ctx, ua.Username, pass, prov.Spec.Keycloak.Realm)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in as admin user/pass (%s): %w", ua.Username, err)
		}
	case prov.Spec.Keycloak.ClientAuth != nil:
		ca := prov.Spec.Keycloak.ClientAuth
		sec, err := r.getSecretVal(ctx, c.Namespace, ca.ClientSecret)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in: %w", err)
		}
		jwt, err = cloak.LoginClient(ctx, ca.ClientID, sec, prov.Spec.Keycloak.Realm)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in as admin service account (%s): %w", ca.ClientID, err)
		}
	}

	cli := gocloak.Client{
		ClientID:                &c.Spec.ClientID,
		RedirectURIs:            &c.Spec.Redirects,
		Name:                    &c.Spec.ClientName,
		BaseURL:                 &c.Spec.Redirects[0],
		ConsentRequired:         gocloak.BoolP(false),
		AdminURL:                &c.Spec.Redirects[0],
		Enabled:                 gocloak.BoolP(true),
		PublicClient:            gocloak.BoolP(false),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
	}

	id, err := cloak.CreateClient(ctx, jwt.AccessToken, prov.Spec.Keycloak.Realm, cli)
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return ctrl.Result{}, fmt.Errorf("error creating new client: %w", err)
	}

	cred, err := cloak.RegenerateClientSecret(ctx, jwt.AccessToken, prov.Spec.Keycloak.Realm, id)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error regenerating secret: %w", err)
	}
	if cred.Value == nil {
		return ctrl.Result{}, fmt.Errorf("regenerated secret had a nil value somehow: %v", cred)
	}

	var sec corev1.Secret
	err = r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      c.Spec.SecretName,
	}, &sec)
	if err != nil {
		sec := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: req.Namespace,
				Name:      c.Spec.SecretName,
			},
			StringData: map[string]string{
				"id":     id,
				"secret": *cred.Value,
			},
		}
		err = r.Create(ctx, &sec)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error creating requested secret %s/%s: %w", req.Namespace, c.Spec.SecretName, err)
		}
	}
	sec.Data = nil
	sec.StringData = map[string]string{
		"id":     id,
		"secret": *cred.Value,
	}

	err = r.Update(ctx, &sec)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error updating requested secret %s/%s: %w", req.Namespace, c.Spec.SecretName, err)
	}

	return ctrl.Result{}, nil
}

func (r *OAuth2ClientReconciler) getSecretVal(ctx context.Context, ns string, sel *corev1.SecretKeySelector) (string, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "OAuth2ClientReconciler.getSecretVal", opentracing.Tags{"name": sel.Name, "namespace": ns})
	defer sp.Finish()
	var sec corev1.Secret
	err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: sel.Name}, &sec)
	if err != nil {
		sp.SetTag("error", true)
		sp.LogKV("error", err)
		return "", fmt.Errorf("error getting secret: %w", err)
	}
	return string(sec.Data[sel.Key]), nil
}

func (r *OAuth2ClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&microcumulusv1beta1.OAuth2Client{}).
		Complete(r)
}
