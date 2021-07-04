package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/opentracing/opentracing-go"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ProxyOpts are used to set up both the kubernetes objects (secrets) and the
// env/args for the oauth2-proxy
type ProxyOpts struct {
	Session      ProxySessionStore `json:"session"`
	CustomBanner string            `json:"customBanner,omitempty"`
	EmailDomain  string            `json:"emailDomain,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Target       Target            `json:"target"`
}

// ProxySessionStore is required, and configures the way that the oauth2-proxy
// stores session data.
type ProxySessionStore struct {
	Redis *RedisSessionStore `json:"redis,omitempty"`
	// Cookie *CookieSessionStore
}

// A RedisSessionStore configures the session to be stored in a redis instance.
// It supports both the known helm chart conventions from bitnami's redis
// server, and a pre-known redis server endpoint and password.
type RedisSessionStore struct {
	Helm  *HelmRedis  `json:"helm,omitempty"`
	Plain *PlainRedis `json:"plain,omitempty"`
}

// HelmRedis indicates the namespace and helm template name prefix used to
// create the redis.
type HelmRedis struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// PlainRedis holds the URL and password to a redis instance. The URL must
// start with `redis://`.
type PlainRedis struct {
	Password string `json:"password,omitempty"`
	URL      string `json:"url,omitempty"`
}

type Target struct {
	Ingress *networkv1.Ingress
	Service *corev1.Service
}

func (po ProxyOpts) targetSvcNamespaceAndName() (string, string) {
	switch {
	case po.Target.Ingress != nil:
		ns := po.Target.Ingress.Namespace
		be := po.Target.Ingress.Spec.Rules[0].HTTP.Paths[0].Backend
		return ns, be.Service.Name
	case po.Target.Service != nil:
		return po.Target.Service.Namespace, po.Target.Service.Name
	}
	return "", ""
}

// type CookieSessionStore struct {
// }

// SetupEnv does the work to set up secrets, and returns the kubernetes Env
// spec for accessing the values it set up, with the varialbe names the
// oauth2-proxy container expects them in. It takes a context, a kubernetes
// client interface implementation, and oidcclient metadata.
func (po ProxyOpts) SetupEnv(ctx context.Context, cs kubernetes.Interface, oClient *OIDCClient) ([]corev1.EnvVar, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "ProxyOpts.SetupEnv")
	defer sp.Finish()

	ns, n := po.targetSvcNamespaceAndName()
	oName := n + "-oauth2-proxy"

	var up string
	switch {
	case po.Target.Ingress != nil:
		be := po.Target.Ingress.Spec.Rules[0].HTTP.Paths[0].Backend
		up = fmt.Sprintf("%s.%s", n, ns)
		if be.Service.Port.Number != 80 {
			up += fmt.Sprintf(":%d", be.Service.Port.Number)
		}
	case po.Target.Service != nil:
		ns, n = po.Target.Service.Namespace, po.Target.Service.Name
		up = fmt.Sprintf("%s.%s:%s", n, ns, &po.Target.Service.Spec.Ports[0].TargetPort)
	}

	bs := make([]byte, 16)
	rand.Read(bs)

	vals := map[string]string{
		"UPSTREAM":        up,
		"OIDC_ISSUER_URL": oClient.IssuerURL,
		"CLIENT_ID":       oClient.ClientID,
		"CLIENT_SECRET":   oClient.ClientSecret,
		"COOKIE_SECRET":   base64.StdEncoding.EncodeToString(bs),
	}

	if po.Session.Redis != nil {
		var redis PlainRedis
		switch {
		case po.Session.Redis.Plain != nil:
			redis = *po.Session.Redis.Plain
		case po.Session.Redis.Helm != nil:
			redisSec, err := cs.CoreV1().Secrets(po.Session.Redis.Helm.Namespace).Get(ctx, po.Session.Redis.Helm.Name+"-redis", metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("couldn't get redis secret: %w", err)
			}
			redis.Password = string(redisSec.Data["redis-password"])
			redis.URL = fmt.Sprintf("redis://%s-redis-master.%s", po.Session.Redis.Helm.Name, po.Session.Redis.Helm.Namespace)
		}
		vals["REDIS_PASSWORD"] = redis.Password
	}

	secData := map[string][]byte{}
	for k, v := range vals {
		secData[k] = []byte(v)
	}

	_, err := cs.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      oName,
			Namespace: ns,
		},
		Data: secData,
	}, metav1.CreateOptions{})
	if err != nil && !strings.Contains(err.Error(), "exists") {
		return nil, fmt.Errorf("error creating secret: %w", err)
	}

	var env []corev1.EnvVar
	for k := range vals {
		env = append(env, corev1.EnvVar{
			Name: "OAUTH2_PROXY_" + k,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: oName,
					},
					Key: k,
				},
			},
		})
	}
	return env, nil
}

// Args turns the ProxyOpts into an argument list for the oauth2-proxy pod
func (po ProxyOpts) Args(ctx context.Context) ([]string, error) {
	args := []string{
		"--upstream=$(OAUTH2_PROXY_UPSTREAM)",
		"--provider=oidc",
		"--provider-display-name=Keycloak",
		fmt.Sprintf("--http-address=0.0.0.0:%d", proxPort),
	}

	if po.EmailDomain != "" {
		args = append(args, "--email-domain="+po.EmailDomain)
	} else {
		args = append(args, "--email-domain=*")
	}

	switch {
	case po.Session.Redis != nil:
		var url string
		switch {
		case po.Session.Redis.Plain != nil:
			url = po.Session.Redis.Plain.URL
		case po.Session.Redis.Helm != nil:
			url = fmt.Sprintf("redis://%s-redis-master.%s", po.Session.Redis.Helm.Name, po.Session.Redis.Helm.Namespace)
		}
		args = append(
			args,
			"--cookie-secure=true",
			"--session-store-type=redis",
			"--redis-connection-url="+url,
		)
		// case po.Session.Cookie != nil:
	}

	if po.CustomBanner != "" {
		args = append(
			args,
			"--banner="+po.CustomBanner,
			"--custom-sign-in-logo=-",
		)
	}

	return args, nil
}
