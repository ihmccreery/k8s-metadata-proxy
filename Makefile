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

.PHONY:	build push

# TAG is the version to build and push to.
PREFIX = gcr.io/google-containers
TAG = 0.1.3

build:
	# We explicitly add "--pull" flag to always fetch the latest version
	# of the base image. This is necessary to avoid using cached local
	# versions of image e.g. when updating insecure base images.
	docker build --pull -t ${PREFIX}/metadata-proxy:$(TAG) .

push: build
	gcloud docker -- push ${PREFIX}/metadata-proxy:$(TAG)
