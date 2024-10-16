package watcher

import (
	"bytes"
	"context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"os"
	"path/filepath"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"strings"
	"time"
)

var logger = ctrl.Log.WithName("watcher")

const defaultStorageDir = "/opt/confidential-containers/kbs/repository"

type SecretSyncer struct {
	k8sClient       kubernetes.Interface
	secretLabel     string
	secretNamespace string
	storageDir      string
}

func NewSecretSyncer(k8sClient kubernetes.Interface, keysSecretLabel, keysSecretNamespace string) (*SecretSyncer, error) {
	return &SecretSyncer{
		k8sClient:       k8sClient,
		secretLabel:     keysSecretLabel,
		secretNamespace: keysSecretNamespace,
		storageDir:      defaultStorageDir,
	}, nil
}

func (p *SecretSyncer) Watch(ctx context.Context) error {
	events := make(chan watch.Event)
	watchTimeout := time.Minute * 5
	if os.Getenv("DEBUG_WATCH") == "true" {
		watchTimeout = time.Minute * 1
	}

	go wait.JitterUntil(func() {
		p.watchSecret(ctx, events, wait.Jitter(watchTimeout, 0.1))
	}, time.Minute, 5.0, true, ctx.Done())

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case e := <-events:
			p.handelEvent(e)
		}
	}

	return nil
}

func (p *SecretSyncer) watchSecret(ctx context.Context, events chan<- watch.Event, watchTimeout time.Duration) error {
	client := p.k8sClient.CoreV1().Secrets(p.secretNamespace)
	ts := int64(watchTimeout / time.Second)

	s, err := fields.ParseSelector(p.secretLabel)
	if err != nil {
		logger.Error(err, "invalid secret label", "SecretLabel", p.secretLabel)
	}

	w, err := client.Watch(ctx, metav1.ListOptions{
		LabelSelector:   s.String(),
		TimeoutSeconds:  &ts,
		ResourceVersion: "0",
		Watch:           true,
	})
	if err != nil {
		logger.Error(err, "watch keys failed")
		return err
	}

loop:
	for {
		select {
		case e, ok := <-w.ResultChan():
			if !ok {
				logger.Info("watch is done")
				break loop
			}
			if e.Type == watch.Error {
				logger.Info("receive error event", "event", e)
				break loop
			}
			events <- e
		}
	}
	w.Stop()
	return nil
}

func (p *SecretSyncer) handelEvent(event watch.Event) {
	if event.Type == watch.Added || event.Type == watch.Modified {
		secret, ok := event.Object.(*v1.Secret)
		if !ok {
			return
		}

		logger.Info("sync data")
		p.syncWithRetry(secret)
	} else if event.Type == watch.Deleted {
		//logger.Info("cleanup keys")
		//p.syncWithRetry(nil)
	}
}

func (p *SecretSyncer) syncWithRetry(secret *v1.Secret) {
	_ = retry.OnError(wait.Backoff{
		Steps:    5,
		Duration: 1 * time.Second,
		Factor:   1.0,
		Jitter:   0.1,
	}, func(err error) bool {
		return err != nil
	}, func() error {
		return p.sync(secret)
	})
}

func (p *SecretSyncer) sync(secret *v1.Secret) error {
	if err := os.MkdirAll(p.storageDir, 0700); err != nil {
		logger.Error(err, "ensure dir failed", "dir", p.storageDir)
		return err
	}

	var errFinal error
	for name, data := range secret.Data {
		if strings.Contains(name, "..") {
			logger.Info("invalid name", "name", name)
			continue
		}

		path := getKeyPath(p.storageDir, name)
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			logger.Error(err, "ensure dir failed", "dir", dir)
			continue
		}

		data = bytes.TrimSpace(data)
		if err := os.WriteFile(path, data, 0600); err != nil {
			logger.Error(err, "save key to file failed", "path", path)
			errFinal = err
		}
		logger.Info("save data success", "path", path)
	}

	return errFinal
}

func getKeyPath(dir, name string) string {
	parts := strings.SplitN(name, ".", 3)
	path := filepath.Join(dir, strings.Join(parts, "/"))
	return path
}

func NewK8sClientOrDie() kubernetes.Interface {
	conf := newConfigOrDie(true)
	return kubernetes.NewForConfigOrDie(conf)
}

func newConfigOrDie(useProtobuf bool) *rest.Config {
	conf := config.GetConfigOrDie()
	//conf.UserAgent = version.GetUserAgent()

	// use protobuf
	if useProtobuf {
		conf.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
		conf.ContentType = "application/vnd.kubernetes.protobuf"
	}

	return conf
}
