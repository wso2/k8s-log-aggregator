**Installation procedure**

1. Execute the create-cert.sh file with necessary arguments
2. Replace values in the files **logstash-collector.yaml**, **logstash_s3_secrets.yaml** and **mutatingwebhookConfiguration.yaml** 
with your values           
3. Issue kubectl create commands for each of the resource yamls.
        
**Usage**

The mutatingwebhook supports 2 modes
1. Complete Sidecar Injection Mode
2. Endpoint exposing Mode

The mutatingwebhook supports 2 modes
1. Complete Sidecar Injection Mode :- All resource files must be deployed
2. Endpoint exposing Mode :- Files (2),(4),(9),(10),(11) must be deployed

**Note**

Dynamic creation of the files
   1. logconf.yaml
   2. logpath-configmap.yaml
   3. values.yaml
   
Allows you to personalize your elasticStack injection at runtime
