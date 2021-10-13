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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OAuth2ClientSpec defines the desired state of OAuth2Client
type OAuth2ClientSpec struct {
	// Provider references the Oauth2ClientProvider or
	// ClusterOauth2ClientProvider that should provision this client.
	Provider        string `json:"provider,omitempty"`
	ClusterProvider string `json:"clusterProvider,omitempty"`

	// ClientID is the optional clientid that the client should have.
	ClientID string `json:"clientID,omitempty"`
	// ClientName is the name of the client in keycloak.
	ClientName string `json:"clientName"`

	// SecretName is the desired secret that should hold the provisioned client's metadata
	SecretName     string            `json:"secretName"`
	SecretTemplate map[string]string `json:"secretTemplate,omitempty"`

	// Redirects is the list of valid redirects for this Client
	Redirects []string `json:"redirects"`
}

// OAuth2ClientStatus defines the observed state of OAuth2Client
type OAuth2ClientStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Reason string `json:"state,omitempty"`
	Ready  bool   `json:"ready"`
}

// +kubebuilder:object:root=true

// OAuth2Client is the Schema for the oauth2clients API
type OAuth2Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OAuth2ClientSpec   `json:"spec,omitempty"`
	Status OAuth2ClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OAuth2ClientList contains a list of OAuth2Client
type OAuth2ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2Client `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OAuth2Client{}, &OAuth2ClientList{})
}
