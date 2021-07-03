package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Nerzal/gocloak/v8"
	"github.com/opentracing/opentracing-go"
	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ProxyOpts struct {
	Sess         ProxySessionStore
	CustomBanner string
	EmailDomain  string
	Annotations  map[string]string
}

type ProxySessionStore struct {
	Redis *RedisSessionStore
	// Cookie *CookieSessionStore
}

type RedisSessionStore struct {
	Helm  *HelmRedis
	Plain *PlainRedis
}

type HelmRedis struct {
	Namespace string
	Name      string
}

// PlainRedis is a
type PlainRedis struct {
	Password string
	URL      string
}

type CookieSessionStore struct {
}

// SetupEnv does the work to set up secrets, and returns the kubernetes Env
// spec for accessing the values it set up, with the varialbe names the
// oauth2-proxy container expects them in.
func (po ProxyOpts) SetupEnv(ctx context.Context, cs kubernetes.Interface, ing *networkv1.Ingress, oClient *OIDCClient, c *gocloak.Client) ([]corev1.EnvVar, error) {
	sp, ctx := opentracing.StartSpanFromContext(ctx, "ProxyOpts.SetupEnv")
	defer sp.Finish()

	be := ing.Spec.Rules[0].HTTP.Paths[0].Backend
	up := be.Service.Name
	if be.Service.Port.Number != 80 {
		up += fmt.Sprintf(":%d", be.Service.Port.Number)
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

	if po.Sess.Redis != nil {
		var redis PlainRedis
		switch {
		case po.Sess.Redis.Plain != nil:
			redis = *po.Sess.Redis.Plain
		case po.Sess.Redis.Helm != nil:
			redisSec, err := cs.CoreV1().Secrets(po.Sess.Redis.Helm.Namespace).Get(ctx, po.Sess.Redis.Helm.Name+"-redis", metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("couldn't get redis secret: %w", err)
			}
			redis.Password = string(redisSec.Data["redis-password"])
			redis.URL = fmt.Sprintf("redis://%s-redis-master.%s", po.Sess.Redis.Helm.Name, po.Sess.Redis.Helm.Namespace)
		}
		vals["REDIS_PASSWORD"] = redis.Password
	}

	secData := map[string][]byte{}
	for k, v := range vals {
		secData[k] = []byte(v)
	}

	_, err := cs.CoreV1().Secrets(ing.Namespace).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *c.Name,
			Namespace: ing.Namespace,
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
						Name: *c.Name,
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
		"--http-address=0.0.0.0:4180",
	}

	if po.EmailDomain != "" {
		args = append(args, "--email-domain="+po.EmailDomain)
	} else {
		args = append(args, "--email-domain=*")
	}

	switch {
	case po.Sess.Redis != nil:
		var url string
		switch {
		case po.Sess.Redis.Plain != nil:
			url = po.Sess.Redis.Plain.URL
		case po.Sess.Redis.Helm != nil:
			url = fmt.Sprintf("redis://%s-redis-master.%s", po.Sess.Redis.Helm.Name, po.Sess.Redis.Helm.Namespace)
		}
		args = append(
			args,
			"--cookie-secure=true",
			"--session-store-type=redis",
			"--redis-connection-url="+url,
		)
		// case po.Sess.Cookie != nil:
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
