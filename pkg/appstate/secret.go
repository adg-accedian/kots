package appstate

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/replicatedhq/kots/pkg/appstate/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	SecretResourceKind = "secret"
	oneWeek            = 7 * 24 * time.Hour
)

func init() {
	registerResourceKindNames(SecretResourceKind, "secrets", "secret")
}

func runSecretController(
	ctx context.Context, clientset kubernetes.Interface, targetNamespace string,
	informers []types.StatusInformer, resourceStateCh chan<- types.ResourceState,
) {
	listwatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return clientset.CoreV1().Secrets(targetNamespace).List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return clientset.CoreV1().Secrets(targetNamespace).Watch(context.TODO(), options)
		},
	}
	informer := cache.NewSharedInformer(
		listwatch,
		&corev1.Secret{},
		time.Minute,
	)

	eventHandler := NewSecretEventHandler(
		filterStatusInformersByResourceKind(informers, SecretResourceKind),
		resourceStateCh,
	)

	runInformer(ctx, informer, eventHandler)
	return
}

type secretEventHandler struct {
	informers       []types.StatusInformer
	resourceStateCh chan<- types.ResourceState
}

func NewSecretEventHandler(informers []types.StatusInformer, resourceStateCh chan<- types.ResourceState) *secretEventHandler {
	return &secretEventHandler{
		informers:       informers,
		resourceStateCh: resourceStateCh,
	}
}

func (h *secretEventHandler) ObjectCreated(obj interface{}) {
	r := h.cast(obj)
	if _, ok := h.getInformer(r); !ok {
		return
	}
	h.resourceStateCh <- makeSecretResourceState(r, CalculateSecretState(r))
}

func (h *secretEventHandler) ObjectUpdated(obj interface{}) {
	r := h.cast(obj)
	if _, ok := h.getInformer(r); !ok {
		return
	}
	h.resourceStateCh <- makeSecretResourceState(r, CalculateSecretState(r))
}

func (h *secretEventHandler) ObjectDeleted(obj interface{}) {
	r := h.cast(obj)
	if _, ok := h.getInformer(r); !ok {
		return
	}
	h.resourceStateCh <- makeSecretResourceState(r, types.StateMissing)
}

func (h *secretEventHandler) cast(obj interface{}) *corev1.Secret {
	r, _ := obj.(*corev1.Secret)
	return r
}

func (h *secretEventHandler) getInformer(r *corev1.Secret) (types.StatusInformer, bool) {
	if r != nil {
		for _, informer := range h.informers {
			if r.Namespace == informer.Namespace && r.Name == informer.Name {
				return informer, true
			}
		}
	}
	return types.StatusInformer{}, false
}

func makeSecretResourceState(r *corev1.Secret, state types.State) types.ResourceState {
	return types.ResourceState{
		Kind:      SecretResourceKind,
		Name:      r.Name,
		Namespace: r.Namespace,
		State:     state,
	}
}

func CalculateSecretState(r *corev1.Secret) types.State {
	if r == nil {
		return types.StateMissing
	}
	now := time.Now()
	foundCert := false
	allValid := true
	anyDegraded := false

	for _, v := range r.Data {
		rest := v
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			foundCert = true
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			remaining := cert.NotAfter.Sub(now)
			if remaining <= 0 {
				return types.StateUnavailable // expired cert
			}
			if remaining < oneWeek {
				anyDegraded = true
			}
		}
	}
	if !foundCert {
		return types.StateMissing // no certificates in secret
	}
	if anyDegraded {
		return types.StateDegraded
	}
	if allValid {
		return types.StateReady
	}
	return types.StateUnavailable // fallback, should not hit
}
