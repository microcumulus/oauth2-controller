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
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

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

const finalizerStringClient = "microcumul.us/oauthclient-controller"

// OAuth2ClientReconciler reconciles a OAuth2Client object
type OAuth2ClientReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=microcumul.us,resources=oauth2clients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=microcumul.us,resources=oauth2clients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;update;delete;create;patch;watch

func (r *OAuth2ClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	defer func() {
		if err := recover(); err != nil {
			r.Log.WithValues("recovered", err).Info("recovered from panic")
		}
	}()
	lg := r.Log.WithValues("oauth2client", req.NamespacedName)
	sp, ctx := opentracing.StartSpanFromContext(ctx, "OAuth2ClientReconciler.Reconcile")
	defer sp.Finish()
	defer func() {
		if err != nil {
			sp.SetTag("error", true)
			sp.LogKV("error", err)
		}
	}()
	var oac v1beta1.OAuth2Client
	err = r.Get(ctx, req.NamespacedName, &oac)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			lg.Info("done deleting client customresource")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("couldn't get client body: %w", err)
	}

	// add finalizer string
	if oac.DeletionTimestamp.IsZero() && !containsString(oac.Finalizers, finalizerStringClient) {
		withFinal := oac.DeepCopy()
		withFinal.Finalizers = append(withFinal.Finalizers, finalizerStringClient)
		err = r.Update(ctx, withFinal)
		lg.V(1).Info("added finalizer; requeuing")
		return ctrl.Result{Requeue: true}, err
	}
	lg.V(1).Info("got req with finalizer")

	var prov v1beta1.ClusterOAuth2ClientProvider
	err = r.Get(ctx, client.ObjectKey{
		Name: oac.Spec.ClusterProvider,
	}, &prov)
	if err != nil {
		lg.Error(err, "could not find provider with %s", oac.Spec.ClusterProvider)
		if !oac.ObjectMeta.DeletionTimestamp.IsZero() {
			if !containsString(oac.Finalizers, finalizerStringClient) {
				return res, nil
			}
			oac2 := oac.DeepCopy()
			oac2.Finalizers = removeString(oac2.Finalizers, finalizerStringClient)
			err = r.Update(ctx, oac2)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("error removing finalizer: %w", err)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("error getting provider: %w", err)
	}

	// TODO: abstract this into a provider interface
	cloak := gocloak.NewClient(prov.Spec.Keycloak.BaseURL)
	var jwt *gocloak.JWT
	switch {
	case prov.Spec.Keycloak.UserAuth != nil:
		ua := prov.Spec.Keycloak.UserAuth

		pass, err := getSecretVal(ctx, r.Client, ua.PasswordRef.Namespace, ua.PasswordRef.SecretKeySelector)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in: %w", err)
		}

		jwt, err = cloak.LoginAdmin(ctx, ua.Username, pass, prov.Spec.Keycloak.Realm)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in as admin user/pass (%s): %w", ua.Username, err)
		}
	case prov.Spec.Keycloak.ClientAuth != nil:
		ca := prov.Spec.Keycloak.ClientAuth
		sec, err := getSecretVal(ctx, r.Client, oac.Namespace, ca.ClientSecret)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in: %w", err)
		}
		jwt, err = cloak.LoginClient(ctx, ca.ClientID, sec, prov.Spec.Keycloak.Realm)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error logging in as admin service account (%s): %w", ca.ClientID, err)
		}
	}

	oac.Spec.ClientID = first(oac.Spec.ClientID, oac.Spec.ClientName)

	// Handling delete
	if !oac.ObjectMeta.DeletionTimestamp.IsZero() {
		if !containsString(oac.Finalizers, finalizerStringClient) {
			return res, nil
		}

		cls, err := cloak.GetClients(ctx, jwt.AccessToken, "master", gocloak.GetClientsParams{
			ClientID: &oac.Spec.ClientID,
		})
		if err != nil {
			lg.Error(err, "couldn't list clients by id")
			return ctrl.Result{}, nil
		}
		if len(cls) == 0 {
			return ctrl.Result{}, nil
		}
		for _, cl := range cls {
			lg.Info("deleting keycloak client", "client", oac.Spec.ClientID)
			err = cloak.DeleteClient(ctx, jwt.AccessToken, prov.Spec.Keycloak.Realm, *cl.ID)
			if err != nil {
				lg.Error(err, "error while deleting keycloak client", "client", oac.Spec.ClientID, "keycloakID", *cl.ID)
			}
		}

		oac2 := oac.DeepCopy()
		oac2.Finalizers = removeString(oac2.Finalizers, finalizerStringClient)
		err = r.Update(ctx, oac2)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error removing finalizer: %w", err)
		}
		return ctrl.Result{}, nil
	}

	var mappers []gocloak.ProtocolMapperRepresentation
	if prov.Spec.Keycloak.GroupClaimName != "" {
		conf := map[string]string{
			"claim.name":           prov.Spec.Keycloak.GroupClaimName,
			"multivalued":          "true",
			"jsonType.label":       "String",
			"id.token.claim":       "true",
			"access.token.claim":   "true",
			"userinfo.token.claim": "true",
			"user.attribute":       "foo", // is this needed? idk. The webUI sends it in devtools.
		}
		mappers = append(mappers, gocloak.ProtocolMapperRepresentation{
			Name:           gocloak.StringP("groups"),
			Protocol:       gocloak.StringP("openid-connect"),
			ProtocolMapper: gocloak.StringP("oidc-usermodel-realm-role-mapper"),
			Config:         &conf,
		})
	}

	cli := gocloak.Client{
		ClientID:                &oac.Spec.ClientID,
		RedirectURIs:            &oac.Spec.Redirects,
		Name:                    &oac.Spec.ClientName,
		BaseURL:                 &oac.Spec.Redirects[0],
		ConsentRequired:         gocloak.BoolP(false),
		AdminURL:                &oac.Spec.Redirects[0],
		Enabled:                 gocloak.BoolP(true),
		PublicClient:            gocloak.BoolP(false),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		ProtocolMappers:         &mappers,
	}

	_, secStr, err := getOrCreateClient(ctx, cloak, *jwt, prov.Spec.Keycloak.Realm, cli)
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return ctrl.Result{}, fmt.Errorf("error creating new client: %w", err)
	}

	data := map[string]string{
		"id":        oac.Spec.ClientID,
		"secret":    secStr,
		"issuerURL": fmt.Sprintf("%s/auth/realms/%s", strings.TrimSuffix(prov.Spec.Keycloak.BaseURL, "/"), strings.TrimPrefix(prov.Spec.Keycloak.Realm, "/")),
	}
	if oac.Spec.SecretTemplate != nil {
		data = map[string]string{}
		for k, tplStr := range oac.Spec.SecretTemplate {
			lg := lg.WithValues("template", tplStr, "templateKey", k)
			buf := &bytes.Buffer{}
			tpl, err := template.New(k).Parse(tplStr)
			if err != nil {
				lg.Error(err, "could not template secret")
				return ctrl.Result{}, err
			}

			err = tpl.Execute(buf, map[string]interface{}{
				"ClientID":     oac.Spec.ClientID,
				"ClientSecret": secStr,
				"IssuerURL":    fmt.Sprintf("%s/auth/realms/%s", strings.TrimSuffix(prov.Spec.Keycloak.BaseURL, "/"), strings.TrimPrefix(prov.Spec.Keycloak.Realm, "/")),
			})
			if err != nil {
				lg.Error(err, "error while executing template")
				return ctrl.Result{}, err
			}

			data[k] = buf.String()
		}
	}

	var sec corev1.Secret
	err = r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      oac.Spec.SecretName,
	}, &sec)
	if err != nil {
		sec := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: req.Namespace,
				Name:      oac.Spec.SecretName,
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: oac.APIVersion,
					Kind:       oac.Kind,
					Name:       oac.Name,
					UID:        oac.UID,
				}},
			},
			StringData: data,
		}
		err = r.Create(ctx, &sec)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("error creating requested secret %s/%s: %w", req.Namespace, oac.Spec.SecretName, err)
		}
		return ctrl.Result{}, nil
	}
	sec.Data = nil
	sec.StringData = data

	err = r.Update(ctx, &sec)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error updating requested secret %s/%s: %w", req.Namespace, oac.Spec.SecretName, err)
	}

	return ctrl.Result{}, nil
}

func getOrCreateClient(ctx context.Context, cli gocloak.GoCloak, jwt gocloak.JWT, realm string, c gocloak.Client) (string, string, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "getOrCreateClient")
	defer sp.Finish()
	cl, err := cli.GetClients(ctx, jwt.AccessToken, "master", gocloak.GetClientsParams{
		ClientID: c.ClientID,
	})
	if err == nil && len(cl) == 1 {
		cred, err := cli.GetClientSecret(ctx, jwt.AccessToken, "master", *cl[0].ID)
		if err != nil {
			return "", "", fmt.Errorf("couldn't get client secret: %w", err)
		}
		if cred.Value != nil && *cred.Value != "" {
			return *cl[0].ClientID, *cred.Value, nil
		}
	}

	id, err := cli.CreateClient(ctx, jwt.AccessToken, realm, c)
	if err != nil {
		return "", "", fmt.Errorf("couldn't create client: %w", err)
	}

	cred, err := cli.RegenerateClientSecret(ctx, jwt.AccessToken, realm, id)
	if err != nil {
		return "", "", fmt.Errorf("error regenerating secret: %w", err)
	}

	if cred.Value == nil {
		return "", "", fmt.Errorf("regenerated secret had a nil value somehow: %v", cred)
	}

	return id, *cred.Value, nil
}

func getSecretVal(ctx context.Context, r client.Client, ns string, sel *corev1.SecretKeySelector) (string, error) {
	if sel == nil {
		return "", nil
	}
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

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) (result []string) {
	for _, item := range slice {
		if item == s {
			continue
		}
		result = append(result, item)
	}
	return
}
