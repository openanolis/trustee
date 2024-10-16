package main

import (
	"flag"
	"gitlab.alibaba-inc.com/cos/coco-charts/dockerfiles/kbs-init/pkg/watcher"
	"log"
	"os"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	secretLabel     = "coco-kbs-resource=true"
	secretNamespace = "coco-kbs"

	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	flag.StringVar(&secretNamespace, "namespace", secretNamespace, "")
	flag.StringVar(&secretLabel, "secret-label", secretLabel, "")
}

func main() {
	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	k8sClient := watcher.NewK8sClientOrDie()
	syncer, err := watcher.NewSecretSyncer(k8sClient, secretLabel, secretNamespace)
	if err != nil {
		setupLog.Error(err, "new SecretSyncer failed")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	setupLog.Info("start syncer")

	go func() {
		if err := syncer.Watch(ctx); err != nil {
			setupLog.Error(err, "start syncer failed")
			os.Exit(2)
		}
	}()

	<-ctx.Done()
	setupLog.Info("start exit")
	time.Sleep(time.Second * 3)
	log.Println("bye bye")
}
