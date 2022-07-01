//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1beta1

import (
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClientAuth) DeepCopyInto(out *ClientAuth) {
	*out = *in
	if in.ClientSecret != nil {
		in, out := &in.ClientSecret, &out.ClientSecret
		*out = new(v1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClientAuth.
func (in *ClientAuth) DeepCopy() *ClientAuth {
	if in == nil {
		return nil
	}
	out := new(ClientAuth)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterOAuth2ClientProvider) DeepCopyInto(out *ClusterOAuth2ClientProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterOAuth2ClientProvider.
func (in *ClusterOAuth2ClientProvider) DeepCopy() *ClusterOAuth2ClientProvider {
	if in == nil {
		return nil
	}
	out := new(ClusterOAuth2ClientProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterOAuth2ClientProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterOAuth2ClientProviderList) DeepCopyInto(out *ClusterOAuth2ClientProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ClusterOAuth2ClientProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterOAuth2ClientProviderList.
func (in *ClusterOAuth2ClientProviderList) DeepCopy() *ClusterOAuth2ClientProviderList {
	if in == nil {
		return nil
	}
	out := new(ClusterOAuth2ClientProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ClusterOAuth2ClientProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterOAuth2ClientProviderSpec) DeepCopyInto(out *ClusterOAuth2ClientProviderSpec) {
	*out = *in
	if in.Keycloak != nil {
		in, out := &in.Keycloak, &out.Keycloak
		*out = new(KeycloakProvider)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterOAuth2ClientProviderSpec.
func (in *ClusterOAuth2ClientProviderSpec) DeepCopy() *ClusterOAuth2ClientProviderSpec {
	if in == nil {
		return nil
	}
	out := new(ClusterOAuth2ClientProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterOAuth2ClientProviderStatus) DeepCopyInto(out *ClusterOAuth2ClientProviderStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterOAuth2ClientProviderStatus.
func (in *ClusterOAuth2ClientProviderStatus) DeepCopy() *ClusterOAuth2ClientProviderStatus {
	if in == nil {
		return nil
	}
	out := new(ClusterOAuth2ClientProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KeycloakProvider) DeepCopyInto(out *KeycloakProvider) {
	*out = *in
	if in.UserAuth != nil {
		in, out := &in.UserAuth, &out.UserAuth
		*out = new(UserAuth)
		(*in).DeepCopyInto(*out)
	}
	if in.ClientAuth != nil {
		in, out := &in.ClientAuth, &out.ClientAuth
		*out = new(ClientAuth)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KeycloakProvider.
func (in *KeycloakProvider) DeepCopy() *KeycloakProvider {
	if in == nil {
		return nil
	}
	out := new(KeycloakProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2Client) DeepCopyInto(out *OAuth2Client) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2Client.
func (in *OAuth2Client) DeepCopy() *OAuth2Client {
	if in == nil {
		return nil
	}
	out := new(OAuth2Client)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OAuth2Client) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientList) DeepCopyInto(out *OAuth2ClientList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]OAuth2Client, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientList.
func (in *OAuth2ClientList) DeepCopy() *OAuth2ClientList {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OAuth2ClientList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientProvider) DeepCopyInto(out *OAuth2ClientProvider) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientProvider.
func (in *OAuth2ClientProvider) DeepCopy() *OAuth2ClientProvider {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientProvider)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OAuth2ClientProvider) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientProviderList) DeepCopyInto(out *OAuth2ClientProviderList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]OAuth2ClientProvider, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientProviderList.
func (in *OAuth2ClientProviderList) DeepCopy() *OAuth2ClientProviderList {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientProviderList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OAuth2ClientProviderList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientProviderSpec) DeepCopyInto(out *OAuth2ClientProviderSpec) {
	*out = *in
	if in.Keycloak != nil {
		in, out := &in.Keycloak, &out.Keycloak
		*out = new(KeycloakProvider)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientProviderSpec.
func (in *OAuth2ClientProviderSpec) DeepCopy() *OAuth2ClientProviderSpec {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientProviderStatus) DeepCopyInto(out *OAuth2ClientProviderStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientProviderStatus.
func (in *OAuth2ClientProviderStatus) DeepCopy() *OAuth2ClientProviderStatus {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientProviderStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientSpec) DeepCopyInto(out *OAuth2ClientSpec) {
	*out = *in
	if in.SecretTemplate != nil {
		in, out := &in.SecretTemplate, &out.SecretTemplate
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Redirects != nil {
		in, out := &in.Redirects, &out.Redirects
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientSpec.
func (in *OAuth2ClientSpec) DeepCopy() *OAuth2ClientSpec {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ClientStatus) DeepCopyInto(out *OAuth2ClientStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ClientStatus.
func (in *OAuth2ClientStatus) DeepCopy() *OAuth2ClientStatus {
	if in == nil {
		return nil
	}
	out := new(OAuth2ClientStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2Proxy) DeepCopyInto(out *OAuth2Proxy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2Proxy.
func (in *OAuth2Proxy) DeepCopy() *OAuth2Proxy {
	if in == nil {
		return nil
	}
	out := new(OAuth2Proxy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OAuth2Proxy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ProxyList) DeepCopyInto(out *OAuth2ProxyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]OAuth2Proxy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ProxyList.
func (in *OAuth2ProxyList) DeepCopy() *OAuth2ProxyList {
	if in == nil {
		return nil
	}
	out := new(OAuth2ProxyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *OAuth2ProxyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ProxySpec) DeepCopyInto(out *OAuth2ProxySpec) {
	*out = *in
	in.SessionStore.DeepCopyInto(&out.SessionStore)
	if in.IngressSelector != nil {
		in, out := &in.IngressSelector, &out.IngressSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Ingress != nil {
		in, out := &in.Ingress, &out.Ingress
		*out = new(v1.ObjectReference)
		**out = **in
	}
	if in.ServiceSelector != nil {
		in, out := &in.ServiceSelector, &out.ServiceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Service != nil {
		in, out := &in.Service, &out.Service
		*out = new(v1.ObjectReference)
		**out = **in
	}
	if in.AllowedGroups != nil {
		in, out := &in.AllowedGroups, &out.AllowedGroups
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ProxyOpts != nil {
		in, out := &in.ProxyOpts, &out.ProxyOpts
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.PodAnnotations != nil {
		in, out := &in.PodAnnotations, &out.PodAnnotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.ExtraRedirects != nil {
		in, out := &in.ExtraRedirects, &out.ExtraRedirects
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ProxySpec.
func (in *OAuth2ProxySpec) DeepCopy() *OAuth2ProxySpec {
	if in == nil {
		return nil
	}
	out := new(OAuth2ProxySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *OAuth2ProxyStatus) DeepCopyInto(out *OAuth2ProxyStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new OAuth2ProxyStatus.
func (in *OAuth2ProxyStatus) DeepCopy() *OAuth2ProxyStatus {
	if in == nil {
		return nil
	}
	out := new(OAuth2ProxyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PasswordRef) DeepCopyInto(out *PasswordRef) {
	*out = *in
	if in.SecretKeySelector != nil {
		in, out := &in.SecretKeySelector, &out.SecretKeySelector
		*out = new(v1.SecretKeySelector)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PasswordRef.
func (in *PasswordRef) DeepCopy() *PasswordRef {
	if in == nil {
		return nil
	}
	out := new(PasswordRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Redis) DeepCopyInto(out *Redis) {
	*out = *in
	in.PasswordRef.DeepCopyInto(&out.PasswordRef)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Redis.
func (in *Redis) DeepCopy() *Redis {
	if in == nil {
		return nil
	}
	out := new(Redis)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SessionStore) DeepCopyInto(out *SessionStore) {
	*out = *in
	in.Redis.DeepCopyInto(&out.Redis)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SessionStore.
func (in *SessionStore) DeepCopy() *SessionStore {
	if in == nil {
		return nil
	}
	out := new(SessionStore)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserAuth) DeepCopyInto(out *UserAuth) {
	*out = *in
	if in.PasswordRef != nil {
		in, out := &in.PasswordRef, &out.PasswordRef
		*out = new(PasswordRef)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserAuth.
func (in *UserAuth) DeepCopy() *UserAuth {
	if in == nil {
		return nil
	}
	out := new(UserAuth)
	in.DeepCopyInto(out)
	return out
}
