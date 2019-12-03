package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/kubernetes/pkg/apis/core/v1"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

// Ignored namespaces which include the kube-system and kube-public namespaces
var ignoredNamespaces = []string {
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationStatusKey = "injection/status"
	standardTestGridLoc = "opt/testgrid/"
)

type mwhServer struct {
	sidecarConfig    *injectionConfig
	logPathConfig    *logConfigs
	server           *http.Server
}

// Webhook Server parameters
type mwhParameters struct {
	port int                 // webhook server port
	certFile string          // path to the x509 certificate for https
	keyFile string           // path to the x509 private key matching `CertFile`
	sidecarCfgFile string    // path to sidecar injector configuration file
	logPathConfigFile string
}

// Stores deployment container name with path to extract logs from
type logPaths struct {
	DeploymentName string `yaml:"deploymentName"`
	ContainerName string  `yaml:"containerName"`
	Path string  `yaml:"path"`
}

// Stores an env variable to be injected
type envVar struct {
	Name string `yaml:"name"`
	Value string `yaml:"value"`
}

// Stores the set of paths which logs need to be injected from or the env variable that need be injected
type logConfigs struct {
	Logpaths []logPaths `yaml:"logpaths"`
	EnvVars []envVar    `"yaml:envvars"`
	OnlyVars string     `"yaml:onlyvars"`
}

// Stores details of the information to be injected
type injectionConfig struct {
	Containers  []corev1.Container   `yaml:"containers"`
	Volumes     []corev1.Volume      `yaml:"volumes"`
	VolumeMounts []corev1.VolumeMount `yaml:"volumeMount"`
	Env []corev1.EnvVar               `yaml:"env"`
	InitContainers []corev1.Container `yaml:"initContainers"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
	_ = v1.AddToScheme(runtimeScheme)
}


/**
 *  load path and deployment container name sets from log path config file
 *  @param logPathconfigFile File name of the log path configuration file
 *  @return Log Path configuration
 */
func loadLogPaths(logPathconfigFile string) (*logConfigs, error){
	yamlFile, err := ioutil.ReadFile(logPathconfigFile)
	glog.Infof(strconv.Itoa(len(yamlFile)))
	if err != nil {
		return nil, err
	}

	var logConfs logConfigs
	if err := yaml.Unmarshal(yamlFile, &logConfs); err != nil{
		return nil,err
	}

	return &logConfs, nil
}

/**
 *  Load injection details from configuration file
 *  @param configFile File name of the injection details configuration file
 *  @return Injection details configuration
 */
func loadConfig(configFile string) (*injectionConfig, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg injectionConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

/**
 *  Checks wether the dep name has any sort of container that requires log files extracted from
 *  @param depname name of the deployment
 *  @param logConfs Log Configuration required by the TestGrid job
 *  @return Boolean wether deployment has containers that needed to be edited
 */
func checkLogpathConfs(depname string, logConfs *logConfigs) bool{
	for _, logLoc := range  logConfs.Logpaths {
		if logLoc.DeploymentName == depname{
			glog.Infof("required in deployment and container pair ", logLoc.DeploymentName)
			return true
		}
	}
	return false
}

/**
 *  Checks wether the TestGrid job only requires that Env variables be injected
 *  @param logConfs Log Configuration required by the TestGrid job
 *  @return Boolean wether only env variables be added
 */
func checkVarRequirement(logConf *logConfigs) bool{
	if logConf.OnlyVars == "true" {
		return true
	}
	return false
}

/**
 *  Checks the pod needs to be mutated
 *  @param ignoredList List of ignored namespaces
 *  @param metadata pods meta data
 *  @param depname Deployment name of the pod
 *  @param logConfs Log Configuration required by the TestGrid job
 *  @return Boolean Wether the pod needs to be mutated
 */
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta, depname string, logConfs *logConfigs) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %v for it' in special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		required = checkLogpathConfs(depname, logConfs) || checkVarRequirement(logConfs)
	}

	glog.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status,
		required)
	return required
}

/**
 *  Adds a container to the pod spec
 *  @param target location to which containers need to be added
 *  @param containerList  containers to be added
 *  @param basePath Location in target where containers need to be added
 *
 *  @return Go patch operation to add the container
 */
func addContainer(target, containerList []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, addContainer := range containerList {
		value = addContainer
		path := basePath
		if first {
			first = false
			value = []corev1.Container{addContainer}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolumeMount(target, volumeMountList []corev1.VolumeMount, basePath string) (patch []patchOperation){
	first := len(target) == 0
	var value interface{}
	for _, addVolumeMount := range volumeMountList {
		value = addVolumeMount
		path := basePath
		if first {
			first = false
			value = []corev1.VolumeMount{addVolumeMount}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addEnvVar(target, envVarList []corev1.EnvVar, basePath string) (patch []patchOperation){
	first := len(target) == 0
	var value interface{}
	for _, addenvVar := range envVarList {
		value = addenvVar
		path := basePath
		if first {
			first = false
			value = []corev1.EnvVar{addenvVar}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func addVolume(target, volumeList []corev1.Volume, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, addVolume := range volumeList {
		value = addVolume
		path := basePath
		if first {
			first = false
			value = []corev1.Volume{addVolume}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}


func addInitContainer(target, initContainerList []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, addInitContainer := range initContainerList {
		value = addInitContainer
		path := basePath
		if first {
			first = false
			value = []corev1.Container{addInitContainer}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation {
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

/**
 *  Updates annotation in pod spec to show that Pod already has data injected to it
 */
func updateAnnotation(target map[string]string, annotations map[string]string) (patch []patchOperation) {
	for key, value := range annotations {
		if target == nil || target[key] == "" {
			target = map[string]string{}
			patch = append(patch, patchOperation {
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation {
				Op:    "replace",
				Path:  "/metadata/annotations/" + key,
				Value: value,
			})
		}
	}
	return patch
}

/**
 *  Finds Log Path for a deployment container name pair
 *  @param logConfs Log Configuration required by the TestGrid job
 *  @return String path to extract logs from the deployment name container name pair
 */
func findLogPath(depName string, containerName string, logConfs *logConfigs ) (path string) {
	for _, logLoc := range  logConfs.Logpaths {
		if logLoc.DeploymentName == depName && logLoc.ContainerName == containerName {
			return logLoc.Path
		}
	}
	glog.Info("No path found for ",depName, containerName,"using default")
	return "/opt/testgrid/logs"
}

// create mutation patch for resources
func createPatch(pod *corev1.Pod,
	sidecarConfig *injectionConfig, annotations map[string]string, logConfs *logConfigs ) ([]byte, error) {

	var patch []patchOperation
	var containerList = pod.Spec.Containers

	if len(containerList) > 0 {
		for index, container := range containerList {
			var envVars = []corev1.EnvVar{}
			Envpath := "/spec/containers/"+strconv.Itoa(index)+"/env"

			for _, envVar := range logConfs.EnvVars {
				var esVar = corev1.EnvVar{Name: envVar.Name, Value: envVar.Value  }
				envVars = append(envVars, esVar)
			}
			patch = append(patch, addEnvVar(container.Env, envVars, Envpath)...)
		}
	}

	if logConfs.OnlyVars != "true" {
		var podRandomName = pod.GenerateName
		var podHash = "-" + pod.Labels["pod-template-hash"] + "-"
		var depName = strings.Replace(podRandomName, podHash, "",1)

		// Adding the environment variables to each container
		for index, container := range containerList {
			Envpath := "/spec/containers/"+strconv.Itoa(index)+"/env"
			patch = append(patch, addEnvVar(container.Env, sidecarConfig.Env, Envpath)...)
		}

		// Adding the init containers
		patch = append(patch, addInitContainer(pod.Spec.InitContainers,
			sidecarConfig.InitContainers, "/spec/initContainers")...)

		// Adding the fixed volumes to each container
		patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)

		// Adding annotations
		patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)


		// Adding volume Mounts to containers
		var sidecarInjectVolMounts = []corev1.VolumeMount{}
		var volumes = []corev1.Volume{}

		for index, container := range containerList {

			var containerInjectVolMounts = []corev1.VolumeMount{}
			var logPath = findLogPath(depName,container.Name,logConfs)
			var injectedVolMount = corev1.VolumeMount{Name:"testgrid-"+strconv.Itoa(index) ,
				MountPath: logPath}
			var sidecarInjectedVolMount = corev1.VolumeMount{Name:"testgrid-"+strconv.Itoa(index) ,
				MountPath:standardTestGridLoc+container.Name}

			var logVolSource = corev1.VolumeSource{EmptyDir: nil}
			var logVolume = corev1.Volume{Name: "testgrid-"+strconv.Itoa(index), VolumeSource: logVolSource}

			sidecarInjectVolMounts = append(sidecarInjectVolMounts, sidecarInjectedVolMount)
			containerInjectVolMounts = append(containerInjectVolMounts, injectedVolMount)

			volumes = append(volumes, logVolume)

			volMountpath := "/spec/containers/"+strconv.Itoa(index)+"/volumeMounts"
			patch = append(patch, addVolumeMount(container.VolumeMounts, containerInjectVolMounts, volMountpath)...)

		}

		// Get Filebeat Sidecar From configmap
		var filebeatSidecar = sidecarConfig.Containers[0];

		sidecarInjectVolMounts = append(sidecarInjectVolMounts, filebeatSidecar.VolumeMounts ...)

		// Add the sidecar
		var sideCarList = []corev1.Container{}
		var sideCar = corev1.Container{
			Name:         filebeatSidecar.Name,
			Image:        filebeatSidecar.Image,
			Env:          sidecarConfig.Env,
			VolumeMounts: sidecarInjectVolMounts,
		}
		sideCarList = append(sideCarList, sideCar)
		patch = append(patch, addContainer(pod.Spec.Containers, sideCarList, "/spec/containers")...)
		// Configuring the sidecar with volume Mounts

		// Adding volumes to container
		patch = append(patch, addVolume(pod.Spec.Volumes, volumes, "/spec/volumes")...)

	}


	return json.Marshal(patch)
}

// main mutation process
func (mwhServer *mwhServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	glog.Info(mwhServer.logPathConfig)
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	var podRandomName = pod.GenerateName
	var podHash = "-" + pod.Labels["pod-template-hash"] + "-"
	var depName = strings.Replace(podRandomName, podHash, "",1)
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta, depName, mwhServer.logPathConfig) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse {
			Allowed: true,
		}
	}

    glog.Infof("no runtime")
	annotations := map[string]string{admissionWebhookAnnotationStatusKey: "injected"}
	patchBytes, err := createPatch(&pod, mwhServer.sidecarConfig, annotations, mwhServer.logPathConfig)
	if err != nil {
		return &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse {
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for webhook server
func (mwhServer *mwhServer) serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse {
			Result: &metav1.Status {
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = mwhServer.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
