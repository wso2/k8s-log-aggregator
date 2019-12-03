package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/golang/glog"
)

func main() {
	var parameters mwhParameters

	// get command line parameters
	flag.IntVar(&parameters.port, "port", 443, "Webhook server port.")
	flag.StringVar(&parameters.certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.sidecarCfgFile, "sidecarCfgFile", "/etc/webhook/config/sidecarconfig.yaml", "File containing the mutation configuration.")
	flag.StringVar(&parameters.logPathConfigFile, "logPathConfigFile", "/etc/webhook/details/logpath-details.yaml", "File containing log path of deployments")
	flag.Parse()
	
	sidecarConfig, err := loadConfig(parameters.sidecarCfgFile)
	if err != nil {
		glog.Errorf("Filed to load configuration: %v", err)
	}

	logPathConfig, err := loadLogPaths(parameters.logPathConfigFile)
	if err != nil {
		glog.Errorf("Filed to load configuration: %v", err)
	}
	
	pair, err := tls.LoadX509KeyPair(parameters.certFile, parameters.keyFile)
	if err != nil {
		glog.Errorf("Filed to load key pair: %v", err)
	}
	
	mwhServer := &mwhServer{
		sidecarConfig:    sidecarConfig,
		logPathConfig:    logPathConfig,
		server:           &http.Server {
			Addr:        fmt.Sprintf(":%v", parameters.port),
			TLSConfig:   &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}
	
	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", mwhServer.serve)
	mwhServer.server.Handler = mux
	
	// start webhook server in new rountine
	go func() {
		if err := mwhServer.server.ListenAndServeTLS("", ""); err != nil {
			glog.Errorf("Filed to listen and serve webhook server: %v", err)
		}
	}()
	
	// listening OS shutdown singal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	
	glog.Infof("Got OS shutdown signal, shutting down wenhook server gracefully...")
	mwhServer.server.Shutdown(context.Background())
}
