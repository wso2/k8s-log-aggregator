/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"k8s-log-aggregator/pkg"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
)

func main() {
	var parameters pkg.MwhParameters

	// get command line parameters
	flag.IntVar(&parameters.WebServerPort, "webServerPort", 443, "Webhook server webServerPort.")
	flag.StringVar(&parameters.X509certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem",
		"File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&parameters.X509KeyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem",
		"File containing the x509 private key to --tlsCertFile.")
	flag.StringVar(&parameters.SidecarConfigFile, "sidecarConfigFile", "/etc/webhook/config/sidecar-config.yaml",
		"File containing the mutation configuration.")
	flag.StringVar(&parameters.LogPathConfigFile, "logPathConfigFile",
		"/etc/webhook/details/logpath-details.yaml", "File containing log path of deployments")
	flag.Parse()

	sidecarConfig, err := pkg.LoadConfig(parameters.SidecarConfigFile)
	if err != nil {
		glog.Errorf("Failed to load Sidecar configuration: %v", err)
	}

	logPathConfig, err := pkg.LoadLogPaths(parameters.LogPathConfigFile)
	if err != nil {
		glog.Errorf("Failed to load Log path configuration: %v", err)
	}

	pair, err := tls.LoadX509KeyPair(parameters.X509certFile, parameters.X509KeyFile)
	if err != nil {
		glog.Errorf("Failed to load key pair: %v", err)
	}

	mwhServer := &pkg.MwhServer{
		SidecarConfig: sidecarConfig,
		LogPathConfig: logPathConfig,
		Server: &http.Server{
			Addr:      fmt.Sprintf(":%v", parameters.WebServerPort),
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
		},
	}

	// Define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", mwhServer.Serve)
	mwhServer.Server.Handler = mux

	// Start webhook server in new routine
	go func() {
		if err := mwhServer.Server.ListenAndServeTLS("", ""); err != nil {
			glog.Errorf("Failed to start listener: %v", err)
		}
	}()

	// Listening OS shutdown signal
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	glog.Infof("Recieved OS shutdown signal, shutting down webhook server gracefully...")
	_ = mwhServer.Server.Shutdown(context.Background())
}
