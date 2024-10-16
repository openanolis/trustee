package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

type DSAKeyFormat struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

var (
	namespace      = ""
	secretNameKeys = ""
	secretNameAuth = ""
	mountPath      = ""
	mountTimeout   = time.Minute * 5
)

func init() {
	flag.StringVar(&namespace, "namespace", "", "")
	flag.StringVar(&secretNameKeys, "secret-name-keys", "kbs-auth-publickey", "")
	flag.StringVar(&secretNameAuth, "secret-name-auth", "kbs-auth-keypair", "")
	flag.StringVar(&mountPath, "mount-path", "/opt/confidential-containers/kbs/user-keys/public.pub", "")
	flag.DurationVar(&mountTimeout, "mount-wait", time.Minute*5, "")
}

func main() {
	flag.Parse()

	if namespace == "" || secretNameKeys == "" || secretNameAuth == "" {
		log.Println("both --namespace, --secret-name-keys and --secret-name-auth are required")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Println("start to init client")
	client, err := newK8sClient()
	if err != nil {
		log.Fatalf("init k8s client failed: %+v", err)
	}

	log.Println("start to generate ed25519 keys")
	pub, priv, err := newEd25519()
	if err != nil {
		log.Fatalf("generate ed25519 keys failed: %+v", err)
	}

	log.Println("start to ensure secrets")
	if err := ensureSecrets(ctx, client, pub, priv); err != nil {
		log.Fatalf("ensure secretes failed: %+v", err)
	}

	log.Printf("start to check mounted file with timeout(%s): %s", mountTimeout, mountPath)

	if err := waitFileMounted(ctx); err != nil {
		log.Fatalf("check mounted file (%s) failed: %+v", mountPath, err)
	}
}

func waitFileMounted(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, mountTimeout)
	defer cancel()

	ticket := time.NewTicker(time.Second)
	defer ticket.Stop()

	var err error
loop:
	for {
		select {
		case <-ctx.Done():
			log.Println("canceled")
			return ctx.Err()
		case <-ticket.C:
			err = checkMountFile()
			if err == nil {
				log.Println("the file is mounted")
				break loop
			}
		}
	}

	return err
}

func checkMountFile() error {
	_, err := os.Stat(mountPath)
	return err
}

func ensureSecrets(ctx context.Context, client kubernetes.Interface, pub, priv []byte) error {
	s1 := newSecret(pub, nil, secretNameKeys)
	err1 := ensureSecret(ctx, client, s1)
	if err1 != nil {
		return fmt.Errorf("ensure secret %s failed: %+v", s1.Name, err1)
	}
	log.Printf("ensured secret %s", s1.Name)

	s2 := newSecret(pub, priv, secretNameAuth)
	err2 := ensureSecret(ctx, client, s2)
	if err2 != nil {
		return fmt.Errorf("ensure secret %s failed: %+v", s2.Name, err2)
	}
	log.Printf("ensured secret %s", s2.Name)

	return nil
}

func ensureSecret(ctx context.Context, client kubernetes.Interface, s *corev1.Secret) error {
	_, err := client.CoreV1().Secrets(namespace).Create(ctx, s, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
	}
	return err
}

func newSecret(pub, priv []byte, name string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"public.pub": pub,
		},
	}
	if len(priv) > 0 {
		s.Data["private.key"] = priv
	}

	return s
}

func newEd25519() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return encodePublicKey(pub), encodePrivateKey(priv), nil
}

func encodePublicKey(key ed25519.PublicKey) []byte {
	k, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil
	}
	b := &pem.Block{Type: "PUBLIC KEY", Bytes: k}
	return pem.EncodeToMemory(b)
}

func encodePrivateKey(key ed25519.PrivateKey) []byte {
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	b := &pem.Block{Type: "PRIVATE KEY", Bytes: k}
	return pem.EncodeToMemory(b)
}

func newK8sClient() (kubernetes.Interface, error) {
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}
