package auth

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A SecretCreator can create a k8s secret
type SecretCreator interface {
	CreateSecret(ctx context.Context, sec *corev1.Secret) (*corev1.Secret, error)
	GetSecret(ctx context.Context, ns, name string) (*corev1.Secret, error)
}

// A ServiceCreator can create a k8s service
type ServiceCreator interface {
	CreateService(ctx context.Context, svc *corev1.Service) (*corev1.Service, error)
}

// IngressLister can list ingresses in a namespace
type IngressLister interface {
	ListIngresses(ctx context.Context, ns string) (*networkv1.IngressList, error)
}

// A IngressCreator can create a k8s ingress
type IngressCreator interface {
	CreateIngress(ctx context.Context, ing *networkv1.Ingress) (*networkv1.Ingress, error)
	UpdateIngress(ctx context.Context, ing *networkv1.Ingress) (*networkv1.Ingress, error)
}

// A DeploymentCreator can create a k8s deployment
type DeploymentCreator interface {
	CreateDeployment(ctx context.Context, dep *appsv1.Deployment) (*appsv1.Deployment, error)
}

// A SecureServiceCreator can create a deployment with secrets held in a
// secret, and a service to expose the deployment.
type SecureServiceCreator interface {
	SecretCreator
	DeploymentCreator
	ServiceCreator
}

// A SecureServiceCreator can create a deployment with secrets held in a
// secret, a service to expose the deployment, and an ingress to expose the
// service outside the cluster.
type SecureStackCreator interface {
	SecureServiceCreator
	IngressCreator
	IngressLister
}

// A KubeClientCreator implements SecureStackCreator with the kubernetes.Interface
type KubeClientCreator struct {
	Kube kubernetes.Interface
}

var _ SecureStackCreator = (*KubeClientCreator)(nil)

func (k *KubeClientCreator) CreateSecret(ctx context.Context, sec *corev1.Secret) (*corev1.Secret, error) {
	return k.Kube.CoreV1().Secrets(sec.Namespace).Create(ctx, sec, metav1.CreateOptions{})
}

func (k *KubeClientCreator) CreateDeployment(ctx context.Context, dep *appsv1.Deployment) (*appsv1.Deployment, error) {
	return k.Kube.AppsV1().Deployments(dep.Namespace).Create(ctx, dep, metav1.CreateOptions{})
}

func (k *KubeClientCreator) CreateService(ctx context.Context, svc *corev1.Service) (*corev1.Service, error) {
	return k.Kube.CoreV1().Services(svc.Namespace).Create(ctx, svc, metav1.CreateOptions{})
}

func (k *KubeClientCreator) CreateIngress(ctx context.Context, ing *networkv1.Ingress) (*networkv1.Ingress, error) {
	return k.Kube.NetworkingV1().Ingresses(ing.Namespace).Create(ctx, ing, metav1.CreateOptions{})
}

func (k *KubeClientCreator) GetSecret(ctx context.Context, ns string, name string) (*corev1.Secret, error) {
	return k.Kube.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
}

func (k *KubeClientCreator) UpdateIngress(ctx context.Context, ing *networkv1.Ingress) (*networkv1.Ingress, error) {
	return k.Kube.NetworkingV1().Ingresses(ing.Namespace).Update(ctx, ing, metav1.UpdateOptions{})
}

func (k *KubeClientCreator) ListIngresses(ctx context.Context, ns string) (*networkv1.IngressList, error) {
	return k.Kube.NetworkingV1().Ingresses(ns).List(ctx, metav1.ListOptions{})
}

// A RuntimeCreator implements SecureStackCreator with the kubernetes.Interface
type RuntimeCreator struct {
	Client client.Client
}

var _ SecureStackCreator = (*RuntimeCreator)(nil)

func (r *RuntimeCreator) CreateSecret(ctx context.Context, sec *corev1.Secret) (*corev1.Secret, error) {
	return sec, r.Client.Create(ctx, sec)
}

func (r *RuntimeCreator) CreateDeployment(ctx context.Context, dep *appsv1.Deployment) (*appsv1.Deployment, error) {
	return dep, r.Client.Create(ctx, dep)
}

func (r *RuntimeCreator) CreateService(ctx context.Context, svc *corev1.Service) (*corev1.Service, error) {
	return svc, r.Client.Create(ctx, svc)
}

func (r *RuntimeCreator) CreateIngress(ctx context.Context, ing *networkv1.Ingress) (*networkv1.Ingress, error) {
	return ing, r.Client.Create(ctx, ing)
}

func (r *RuntimeCreator) GetSecret(ctx context.Context, ns string, name string) (*corev1.Secret, error) {
	var sec corev1.Secret
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &sec)
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

func (r *RuntimeCreator) UpdateIngress(ctx context.Context, ing *networkv1.Ingress) (*networkv1.Ingress, error) {
	err := r.Client.Update(ctx, ing)
	if err != nil {
		return nil, err
	}
	return ing, nil
}

func (r *RuntimeCreator) ListIngresses(ctx context.Context, ns string) (*networkv1.IngressList, error) {
	var list *networkv1.IngressList
	err := r.Client.List(ctx, list, &client.ListOptions{Namespace: ns})
	if err != nil {
		return nil, err
	}
	return list, nil
}
