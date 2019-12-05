####Prerequisites 

1. Helm

####Installation procedure

1. Execute the create-cert.sh file with necessary arguments
2. Create a new helm project by issuing
        
            helm create
            
3. Add the resource yaml files into the templates directory of the newly 
create helm chart replacing and removing any generated files
4. Generate the values.yaml file based on your Elastic Search endpoint and
other credentials
5. Issue the command 

        ca_bundle=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}')
        
   and use the value as the ca_bundle value in the values.yaml file
   
6. Issue the command to install the mutating webhook

        Helm install <name> .
        
The mutatingwebhook supports 2 modes
1. Complete Sidecar Injection Mode
2. Endpoint exposing Mode

By setting the sidecarReq value of the values.yaml this modes can be achieved. with the required files being generated.
#### Note
Dynamic creation of the files
   1. logconf.yaml
   2. logpath-configmap.yaml
   3. values.yaml
   
Allow you to personalize your elasticStack injection at runtime
        