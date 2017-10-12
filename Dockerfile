# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# TODO(ihmccreery) Change this to busybox, etc. once iptables stuff is removed.
FROM gcr.io/google_containers/debian-base-amd64:0.3
LABEL maintainer "ihmccreery@google.com"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
  apt-utils && clean-install iptables

# Place our wrapper script into the image.
COPY start-proxy.sh /
COPY metadata_proxy /

ENTRYPOINT ["/start-proxy.sh"]
