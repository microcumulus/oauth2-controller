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
	"log"

	"github.com/go-logr/logr"
	"github.com/opentracing/opentracing-go"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

var kube kubernetes.Interface

func init() {
	conf, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	kube, err = kubernetes.NewForConfig(conf)
	if err != nil {
		log.Fatal(err)
	}
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

	// your logic here
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

	// TODO actually create the client

	return ctrl.Result{}, nil
}

func (r *OAuth2ClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&microcumulusv1beta1.OAuth2Client{}).
		Complete(r)
}
