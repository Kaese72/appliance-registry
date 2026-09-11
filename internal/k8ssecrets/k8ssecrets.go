// Package k8ssecrets writes/deletes the cloud-connect-secret-<id> Secret
// each claimed Appliance needs on the cloud side - see the README's
// "Cloud-side cloud-connect-server provisioning" section. Secret material
// is written directly via the Kubernetes API and never stored in this
// service's own database, so this is the only place that value exists once
// the claim/rotate response has been sent.
package k8ssecrets

import (
	"context"
	"fmt"

	"github.com/Kaese72/appliance-registry/internal/logging"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type SecretWriter interface {
	// WriteApplianceSecret creates or overwrites the "auth" key of
	// cloud-connect-secret-<applianceID> with authValue.
	WriteApplianceSecret(ctx context.Context, applianceID int64, authValue string) error
	// DeleteApplianceSecret removes cloud-connect-secret-<applianceID>. A
	// missing Secret is not an error.
	DeleteApplianceSecret(ctx context.Context, applianceID int64) error
}

func secretName(applianceID int64) string {
	return fmt.Sprintf("cloud-connect-secret-%d", applianceID)
}

type clientSecretWriter struct {
	client    kubernetes.Interface
	namespace string
}

func (w clientSecretWriter) WriteApplianceSecret(ctx context.Context, applianceID int64, authValue string) error {
	name := secretName(applianceID)
	secrets := w.client.CoreV1().Secrets(w.namespace)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: w.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "appliance-registry",
			},
		},
		StringData: map[string]string{
			"auth": authValue,
		},
	}
	if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		existing.StringData = map[string]string{"auth": authValue}
		if _, err := secrets.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}
	return nil
}

func (w clientSecretWriter) DeleteApplianceSecret(ctx context.Context, applianceID int64) error {
	err := w.client.CoreV1().Secrets(w.namespace).Delete(ctx, secretName(applianceID), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// noopSecretWriter is used when this service is not running in-cluster
// (e.g. local development) so it can still be exercised without a real
// Kubernetes API to talk to. It logs loudly rather than silently pretending
// to succeed.
type noopSecretWriter struct{}

func (noopSecretWriter) WriteApplianceSecret(ctx context.Context, applianceID int64, _ string) error {
	logging.Warn(fmt.Sprintf("no Kubernetes client configured; skipped writing cloud-connect-secret for appliance %d", applianceID), ctx)
	return nil
}

func (noopSecretWriter) DeleteApplianceSecret(ctx context.Context, applianceID int64) error {
	logging.Warn(fmt.Sprintf("no Kubernetes client configured; skipped deleting cloud-connect-secret for appliance %d", applianceID), ctx)
	return nil
}

// NewSecretWriter builds a SecretWriter using in-cluster credentials. If
// those aren't available (not running inside a Kubernetes Pod), it falls
// back to a no-op implementation instead of failing startup, so the rest of
// the service (registration, listing, ...) still works in local dev.
func NewSecretWriter(namespace string) SecretWriter {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		logging.Warn("not running in-cluster; cloud-connect Secret writes are disabled: "+err.Error(), context.Background())
		return noopSecretWriter{}
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		logging.Warn("failed to build Kubernetes client; cloud-connect Secret writes are disabled: "+err.Error(), context.Background())
		return noopSecretWriter{}
	}
	return clientSecretWriter{client: clientset, namespace: namespace}
}
