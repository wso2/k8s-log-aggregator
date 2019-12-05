# k8s-log-aggregator
Mutating Web-hook Deployment for ElasticStack injection in k8s and helm

####Architecture of Top Down ElasticStack Deployment

![Architecture](docs/Sample%20full%20elasticStack%20deployment.png)

####Prerequsites

1. Ensure that you are running a Kubernetes cluster with version greater 
than 1.9 by issuing the command

        kubectl api-versions | grep admissionregistration.k8s.io/v1beta1

    The result should be
    
        admissionregistration.k8s.io/v1beta1
        
2. Kuberenetes client version (kubectl) version greater than 1.12
3. The project is written using Go. Install Go for you OS by reffering the
following link

4. The project uses dep as the dependency management tool for Go. Install dep 
by the following command

        go get -u github.com/golang/dep/cmd/dep
        
5. Docker is used to create the container. It can be installed from 

6. A Dockerhub account is required to push the MutatingWebhook Image to a 
central repo

7. For the mutatingwebhook to work the namespace must be injected with the following labels
        
        kubectl label namespace ${namespace} namespace=${namespace}
        kubectl label namespace ${namespace} sidecar-injector=enabled
        
####Building the Docker Image

To build the Docker Image issue the following command

        ./build
                
####Description of resource files

1. filebeatyaml.yaml :- Contains the configmap of the filebeat.yml file
2. injectionConfigmap :- Contains information of the details that would be injected into the containers
3. logconf.yaml :- Contains the Logstash.conf file describing the pipeline of the Logstash container
4. logpath-configmap.yaml :- Contains details of the log path locations of the contains which need sidecar injection. 
Additionally contains any environment variables that need be added
5. logstash-collector.yaml :- Main deployment of the Logstash Collector
6. Logstash-service.yaml :- Expose the Logstash container
7. Logstash_s3_secrets.yaml :- Secrets for aws crednetials in Logstash s3 output plugin
8. logstashyaml.yaml :- Configmap containing the logstash.yml file
9. mutatingwebhookConfiguration.yaml :- Contains the mutatingwebhookConfiguration
10. mutatingwebhookDeployment.yaml :- Contains the mutatingwebhook Deployment
11. mutatingwebhookService.yaml :- Contains the service for exposing the mutating webhook
12. create-cert.sh :- Create Generate certificate suitable for use with an sidecar-injector webhook service.

**All resource files are generated under the assumption of helm is being used to create
the deployment**

####Installation
1. [Through Helm](docs/HELM_INSTALLATION.MD)
2. [Through Kubernetes](docs/K8S_INSTALLATION.MD)
