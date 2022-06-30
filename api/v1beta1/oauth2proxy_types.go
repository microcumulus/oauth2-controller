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

package v1beta1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// OAuth2ProxySpec defines the desired state of OAuth2Proxy
type OAuth2ProxySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	ClusterClientProvider string       `json:"clusterClientProvider,omitempty"`
	ClientProvider        string       `json:"clientProvider,omitempty"`
	ClientType            string       `json:"clientType,omitempty"`
	SessionStore          SessionStore `json:"sessionStore"`

	// IngressSelector instructs the controller to replace all ingresses that
	// match a specified selector.
	IngressSelector *metav1.LabelSelector `json:"ingressSelector,omitempty"`

	// Ingress instructs the controller to replace an ingress with a protected
	// proxied version.
	Ingress *v1.ObjectReference `json:"ingress"`

	// ServiceSelector instructs the controller to create proxies for all
	// services that match a given selector
	ServiceSelector *metav1.LabelSelector `json:"serviceSelector,omitempty"`

	// Service instructs the controller to target a specific single service.
	Service *v1.ObjectReference `json:"service,omitempty"`

	AllowedGroups []string `json:"allowedGroups,omitempty"`

	// All ProxyOpts that can be passed as environment variables can be specified
	// here. See
	// https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/overview
	// (or the latest equivalent of
	// https://github.com/oauth2-proxy/oauth2-proxy/blob/e6223383e5ff68709afe8e47d3e91b499e5802ad/docs/docs/configuration/overview.md)
	// if the page is gone.
	ProxyOpts map[string]string `json:"proxyOpts,omitempty"`
}

type SessionStore struct {
	Redis Redis `json:"redis"`
}

type Redis struct {
	Host        string      `json:"host"`
	PasswordRef PasswordRef `json:"passwordRef,omitempty"`
}

// OAuth2ProxyStatus defines the observed state of OAuth2Proxy
type OAuth2ProxyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Ready   bool   `json:"ready"`
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Ingress",type=string,JSONPath=`.spec.ingress.name`

// OAuth2Proxy is the Schema for the oauth2proxies API
type OAuth2Proxy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OAuth2ProxySpec   `json:"spec,omitempty"`
	Status OAuth2ProxyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OAuth2ProxyList contains a list of OAuth2Proxy
type OAuth2ProxyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2Proxy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OAuth2Proxy{}, &OAuth2ProxyList{})
}
