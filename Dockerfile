# Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM alpine:latest
# Usage
# arguments
# -- webServerPort - Port web server runs on
# -- tlsCertFile   - Path to tls certificate file
# -- tlsKeyFile    - Path to tls key file
# -- sidecarConfigFile - Path to sidecar configuration file
# -- logPathConfigFile - Path to Log Path configuration file
ADD k8s-log-aggregator /k8s-log-aggregator
ENTRYPOINT ["./k8s-log-aggregator"]