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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// OAuth2ClientProviderSpec defines the desired state of OAuth2ClientProvider
type OAuth2ClientProviderSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Keycloak providers can provision oauth2 clients from openid connect
	Keycloak *KeycloakProvider `json:"keycloak"`
}

// KeycloakProvider holds the necessary data to create OAuth2 clients
type KeycloakProvider struct {
	// BaseURL is the externally-accessible base URL for the keycloak server
	BaseURL string `json:"baseURL"`
	// Realm is the keycloak Realm for which we have credentials and will provision clients.
	Realm string `json:"realm"`
	// UserAuth allows the provider code to authenticate with a keycloak user/password
	UserAuth *UserAuth
	// ClientAuth allows the provider code to authenticate with a keycloak client
	// credential grant
	ClientAuth *ClientAuth
}

// UserAuth allows the provider to authenticate with a known keycloak user/pass
// combination. Must have admin permissions.
type UserAuth struct {
	Username string                    `json:"username"`
	Password *corev1.SecretKeySelector `json:"password"`
}

// ClientAuth allows the use of a keycloak client that has a ServiceAccount
// enabled with an admin role. See
// https://github.com/keycloak/keycloak-documentation/blob/b572fcff07950ac8c05c0d2f9e395234aea63cdd/server_admin/topics/clients/oidc/service-accounts.adoc
type ClientAuth struct {
	ClientID     string                    `json:"clientID"`
	ClientSecret *corev1.SecretKeySelector `json:"clientSecret"`
}

// OAuth2ClientProviderStatus defines the observed state of OAuth2ClientProvider
type OAuth2ClientProviderStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Reason string `json:"state,omitempty"`
	Ready  bool   `json:"ready"`
}

// +kubebuilder:object:root=true

// OAuth2ClientProvider is the Schema for the oauth2clientproviders API
type OAuth2ClientProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OAuth2ClientProviderSpec   `json:"spec,omitempty"`
	Status OAuth2ClientProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OAuth2ClientProviderList contains a list of OAuth2ClientProvider
type OAuth2ClientProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2ClientProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OAuth2ClientProvider{}, &OAuth2ClientProviderList{})
}
