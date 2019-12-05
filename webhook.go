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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

// Ignored namespaces which include the kube-system and kube-public namespaces
var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	admissionWebhookAnnotationStatusKey = "injection/status"
	standardTestGridLoc                 = "opt/testgrid/"
	injectedIdentificationConstant      = "injected"
)

type mwhServer struct {
	sidecarConfig *injectionConfig
	logPathConfig *logConfigs
	server        *http.Server
}

// Web-hook server parameters
type mwhParameters struct {
	webServerPort     int
	x509certFile      string
	x509KeyFile       string
	sidecarConfigFile string
	logPathConfigFile string
}

// Stores deployment container name with path to extract logs from
type logPath struct {
	DeploymentName string `yaml:"deploymentName"`
	ContainerName  string `yaml:"containerName"`
	Path           string `yaml:"path"`
}

// Stores an env variable to be injected
type envVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// Stores the set of paths which logs need to be injected from or the env variable that need be injected
type logConfigs struct {
	Logpaths []logPath `yaml:"logPaths"`
	EnvVars  []envVar  `yaml:"envVars"`
	OnlyVars string    `yaml:"onlyVars"`
}

// Stores details of the information to be injected
type injectionConfig struct {
	Containers     []corev1.Container   `yaml:"containers"`
	Volumes        []corev1.Volume      `yaml:"volumes"`
	VolumeMounts   []corev1.VolumeMount `yaml:"volumeMount"`
	Env            []corev1.EnvVar      `yaml:"env"`
	InitContainers []corev1.Container   `yaml:"initContainers"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

/**
 *  Load path and deployment container name sets from log path config file
 *  @param logPathconfigFile File name of the log path configuration file
 *  @return Log Path configuration
 */
func loadLogPaths(logPathconfigFile string) (*logConfigs, error) {
	yamlFile, err := ioutil.ReadFile(logPathconfigFile)

	if err != nil {
		return nil, err
	}

	var logConfs logConfigs
	if err := yaml.Unmarshal(yamlFile, &logConfs); err != nil {
		return nil, err
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
 *  Checks whether the dep name has any sort of container that requires log files extracted from
 *  @param depname name of the deployment
 *  @param logConfs Log Configuration required by the TestGrid job
 *  @return Boolean wether deployment has containers that needed to be edited
 */
func checkLogPathConfs(depName string, logConfs *logConfigs) bool {
	for _, logLoc := range logConfs.Logpaths {
		if logLoc.DeploymentName == depName {
			glog.Infof("Mutation required in deployment and container pair %s", logLoc.DeploymentName)
			return true
		}
	}
	return false
}

/**
 *  Checks whether the TestGrid job only requires that Env variables be injected
 *  @param logConfs Log Configuration required by the TestGrid job
 *  @return Boolean wether only env variables be added
 */
func checkEnvVarRequirement(logConf *logConfigs) bool {
	if logConf == nil {
		glog.Error("Log configuration not provided check config map for errors")
		return false
	}
	if logConf.OnlyVars == "true" {
		return true
	}
	return false
}

/**
 *  Checks the pod needs to be mutated
 *  @param ignoredList List of ignored namespaces
 *  @param metadata pods meta data
 *  @param depName Deployment name of the pod
 *  @param logConfigurations Log Configuration required by the TestGrid job
 *  @return Boolean Whether the pod needs to be mutated
 */
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta, depName string,
	logConfigurations *logConfigs) bool {

	// Skip special kubernetes system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			glog.Infof("Skip mutation for %s for it' in special namespace:%s", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[admissionWebhookAnnotationStatusKey]

	// Determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == injectedIdentificationConstant {
		required = false
	} else {
		required = checkLogPathConfs(depName, logConfigurations) || checkEnvVarRequirement(logConfigurations)
	}

	glog.Infof("Mutation policy for %s/%s: status: %q required:%b", metadata.Namespace, metadata.Name, status,
		required)
	return required
}

/**
 *  Adds a container to the pod spec
 *  @param target Location to which containers need to be added
 *  @param containerList  Containers to be added
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
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

/**
 *  Adds a volume mount to the pod spec
 *  @param target Location to which volume mount need to be added
 *  @param volumeMountList Volume Mounts that to be added
 *  @param basePath Location in target where volume Mounts need to be added
 *
 *  @return Go patch operation to add the volume mounts
 */
func addVolumeMount(target, volumeMountList []corev1.VolumeMount, basePath string) (patch []patchOperation) {
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
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

/**
 *  Adds a environment variables to the pod spec
 *  @param target Location to which environment variables need to be added
 *  @param envVarList environment variables that to be added
 *  @param basePath Location in target where environment variables need to be added
 *
 *  @return Go patch operation to add the environment variables
 */
func addEnvVar(target, envVarList []corev1.EnvVar, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, addEnvVar := range envVarList {
		value = addEnvVar
		path := basePath
		if first {
			first = false
			value = []corev1.EnvVar{addEnvVar}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

/**
 *  Adds a volumes to the pod spec
 *  @param target Location to which volumes need to be added
 *  @param volumeList volumes that to be added
 *  @param basePath Location in target where volumes need to be added
 *
 *  @return Go patch operation to add the volumes
 */
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
		patch = append(patch, patchOperation{
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
		patch = append(patch, patchOperation{
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
			patch = append(patch, patchOperation{
				Op:   "add",
				Path: "/metadata/annotations",
				Value: map[string]string{
					key: value,
				},
			})
		} else {
			patch = append(patch, patchOperation{
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
 *  @param logConfigurations Log Configuration required by the TestGrid job
 *  @return string Path to extract logs from the deployment name container name pair
 */
func findLogPath(depName string, containerName string, logConfigurations *logConfigs) (path string) {
	for _, logLoc := range logConfigurations.Logpaths {
		if logLoc.DeploymentName == depName && logLoc.ContainerName == containerName {
			return logLoc.Path
		}
	}
	glog.Info("No path found for ", depName, containerName, "using default")
	return "/opt/testgrid/logs"
}

// Derive the deployment name using randomly generated name and hash
func deriveDepName(podRandomName string, podHash string) string {
	var depName = strings.Replace(podRandomName, podHash, "", 1)
	return depName
}

// Create mutation patch for resources
func createPatch(pod *corev1.Pod, sidecarConfig *injectionConfig, annotations map[string]string,
	logConfs *logConfigs) ([]byte, error) {

	var patch []patchOperation
	var containerList = pod.Spec.Containers

	for index, container := range containerList {
		var envVars []corev1.EnvVar
		envPath := "/spec/containers/" + strconv.Itoa(index) + "/env"

		for _, envVar := range logConfs.EnvVars {
			var esVar = corev1.EnvVar{Name: envVar.Name, Value: envVar.Value}
			envVars = append(envVars, esVar)
		}
		patch = append(patch, addEnvVar(container.Env, envVars, envPath)...)
	}

	if logConfs.OnlyVars != "true" {

		var depName = deriveDepName(pod.GenerateName, "-"+pod.Labels["pod-template-hash"]+"-")

		// Adding the environment variables to each container
		for index, container := range containerList {
			envPath := "/spec/containers/" + strconv.Itoa(index) + "/env"
			patch = append(patch, addEnvVar(container.Env, sidecarConfig.Env, envPath)...)
		}

		// Adding the init containers
		patch = append(patch, addInitContainer(pod.Spec.InitContainers, sidecarConfig.InitContainers,
			"/spec/initContainers")...)

		// Adding the fixed volumes to each container
		patch = append(patch, addVolume(pod.Spec.Volumes, sidecarConfig.Volumes, "/spec/volumes")...)

		// Adding annotations
		patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)

		// Adding volume Mounts to containers
		var sidecarInjectVolMounts []corev1.VolumeMount
		var volumes []corev1.Volume

		for index, container := range containerList {

			var containerInjectVolMounts []corev1.VolumeMount
			var logPath = findLogPath(depName, container.Name, logConfs)
			var injectedVolMount = corev1.VolumeMount{Name: "testgrid-" + strconv.Itoa(index),
				MountPath: logPath}
			var sidecarInjectedVolMount = corev1.VolumeMount{Name: "testgrid-" + strconv.Itoa(index),
				MountPath: standardTestGridLoc + container.Name}

			var logVolSource = corev1.VolumeSource{EmptyDir: nil}
			var logVolume = corev1.Volume{Name: "testgrid-" + strconv.Itoa(index), VolumeSource: logVolSource}

			sidecarInjectVolMounts = append(sidecarInjectVolMounts, sidecarInjectedVolMount)
			containerInjectVolMounts = append(containerInjectVolMounts, injectedVolMount)

			volumes = append(volumes, logVolume)

			volMountpath := "/spec/containers/" + strconv.Itoa(index) + "/volumeMounts"
			patch = append(patch, addVolumeMount(container.VolumeMounts, containerInjectVolMounts, volMountpath)...)

		}

		// Get file-beat Sidecar from config map
		var filebeatSidecar = sidecarConfig.Containers[0]

		sidecarInjectVolMounts = append(sidecarInjectVolMounts, filebeatSidecar.VolumeMounts...)

		// Add the sidecar
		var sideCarList []corev1.Container
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

// Main mutation process
func (mwhServer *mwhServer) mutate(admissionReview *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	glog.Info(mwhServer.logPathConfig)
	req := admissionReview.Request
	var pod corev1.Pod

	if req == nil {
		glog.Error("Received null request Object")
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: "Null request Object",
			},
		}
	}

	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		glog.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionReview for Kind=%v, Namespace=%s Name=%s (%s) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// Determine whether to perform mutation
	var depName = deriveDepName(pod.GenerateName, "-"+pod.Labels["pod-template-hash"]+"-")
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta, depName, mwhServer.logPathConfig) {
		glog.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := map[string]string{admissionWebhookAnnotationStatusKey: injectedIdentificationConstant}
	patchBytes, err := createPatch(&pod, mwhServer.sidecarConfig, annotations, mwhServer.logPathConfig)
	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	glog.Infof("AdmissionResponse: patch=%s\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// Serve method for web-hook server
func (mwhServer *mwhServer) serve(responseWriter http.ResponseWriter, k8srequest *http.Request) {
	glog.Info("code review applied")
	var body []byte
	var err error
	if k8srequest.Body != nil {
		if body, err = ioutil.ReadAll(k8srequest.Body); err != nil {
			glog.Errorf("Error reading request %v", err)
			http.Error(responseWriter, "Error reading request", http.StatusBadRequest)
			return
		}
	}
	if len(body) == 0 {
		glog.Error("empty body")
		http.Error(responseWriter, "Empty body", http.StatusBadRequest)
		return
	}

	// Verify that the content type is accurate
	contentType := k8srequest.Header.Get("Content-Type")
	if contentType != "application/json" {
		glog.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(responseWriter, "Invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	originalAdmissionReview := v1beta1.AdmissionReview{}
	// Ability to decode to Admission review object is only required
	if _, _, err := deserializer.Decode(body, nil, &originalAdmissionReview); err != nil {
		glog.Errorf("Can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = mwhServer.mutate(&originalAdmissionReview)
	}

	mutatedAdmissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		mutatedAdmissionReview.Response = admissionResponse
		if originalAdmissionReview.Request != nil {
			mutatedAdmissionReview.Response.UID = originalAdmissionReview.Request.UID
		}
	}

	resp, err := json.Marshal(mutatedAdmissionReview)
	if err != nil {
		glog.Errorf("Can't encode response: %v", err)
		http.Error(responseWriter, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	glog.Infof("Ready to write reponse ...")
	if _, err := responseWriter.Write(resp); err != nil {
		glog.Errorf("Can't write response: %v", err)
		http.Error(responseWriter, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}
