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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterOAuth2ClientProviderSpec defines the desired state of ClusterOAuth2ClientProvider
type ClusterOAuth2ClientProviderSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of ClusterOAuth2ClientProvider. Edit ClusterOAuth2ClientProvider_types.go to remove/update
	Foo string `json:"foo,omitempty"`
}

// ClusterOAuth2ClientProviderStatus defines the observed state of ClusterOAuth2ClientProvider
type ClusterOAuth2ClientProviderStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// ClusterOAuth2ClientProvider is the Schema for the clusteroauth2clientproviders API
type ClusterOAuth2ClientProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterOAuth2ClientProviderSpec   `json:"spec,omitempty"`
	Status ClusterOAuth2ClientProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterOAuth2ClientProviderList contains a list of ClusterOAuth2ClientProvider
type ClusterOAuth2ClientProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterOAuth2ClientProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterOAuth2ClientProvider{}, &ClusterOAuth2ClientProviderList{})
}
