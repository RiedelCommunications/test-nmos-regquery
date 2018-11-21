# Copyright (C) 2018 Riedel Communications GmbH & Co. KG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.f
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest
import uuid
import time
import copy
import defines
import tools


class testRegistrationAPIBasicRoot(tools.TestBase):
    """Basic tests for the Regstration (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/registration
        # -----------------------------------------------------------------------------
        self.test_urls = [defines._BASE_REGISTRATION_URL, defines._BASE_REGISTRATION_URL + "/"]

    def test(self):
        for url in self.test_urls:
            with self.subTest(url=url):
                # Check OPTIONS request
                if defines.CHECK_OPTIONS_RESPONSE:
                    expected_methods = ["OPTIONS", "GET"]
                    if defines.CHECK_HEAD_RESPONSE:
                        expected_methods.append("HEAD")
                    self.options_request(url=url, expected_methods=expected_methods)

                # Check HEAD request
                if defines.CHECK_HEAD_RESPONSE:
                    self.head_request(url=url)

                # Check GET request
                self.get_request(url=url,
                                 request_headers={"accept": "application/json"},
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response_keys=[v + "/" for v in defines.VERSIONS])

                # Check GET request with default content-type
                self.get_request(url=url,
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response_keys=[v + "/" for v in defines.VERSIONS])


class testRegistrationAPIBasicVersions(tools.TestBase):
    """Testing vX.X endpoints for the Registration (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/registration/vX.X/?
        # -----------------------------------------------------------------------------
        self.test_urls = ["{}/{}".format(defines._BASE_REGISTRATION_URL, v) for v in defines.VERSIONS]
        self.test_urls.extend(["{}/{}/".format(defines._BASE_REGISTRATION_URL, v) for v in defines.VERSIONS])

    def test(self):
        for url in self.test_urls:
            with self.subTest(url=url):
                # Check OPTIONS request
                if defines.CHECK_OPTIONS_RESPONSE:
                    expected_methods = ["OPTIONS", "GET"]
                    if defines.CHECK_HEAD_RESPONSE:
                        expected_methods.append("HEAD")
                    self.options_request(url=url, expected_methods=expected_methods)

                # Check HEAD request
                if defines.CHECK_HEAD_RESPONSE:
                    self.head_request(url=url)

                # Check GET request
                self.get_request(url=url,
                                 request_headers={"accept": "application/json"},
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response=["resource/",
                                                         "health/"])

                # Check GET request with default content-type
                self.get_request(url=url,
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response=["resource/",
                                                         "health/"])


class testRegistrationAPIBasicResource(tools.TestBase):
    """Test posting resources"""

    def setUp(self):
        self.test_arr = [
            {
                "version": v,
                "resource_url": "{}/{}/resource".format(defines._BASE_REGISTRATION_URL, v),
                "health_url": "{}/{}/health/nodes/".format(defines._BASE_REGISTRATION_URL, v)
            } for v in defines.VERSIONS
        ]
        self.sample = tools.sample_data()
        self.random_id = str(uuid.uuid4())
        self.validator = tools.JsonSchemaValidator()

    def test_post_invalid(self):
        """Test POSTing invalid resources"""
        # Post invalid resource
        for curr in self.test_arr:
            for resource in defines._RESOURCES:
                invalid_resource = copy.deepcopy(
                    self.sample.get_sample_data(resource=resource, version=curr["version"]))
                invalid_resource["data"].pop("id", None)
                with self.subTest(url=curr["resource_url"], data=invalid_resource):
                    result = self.post_request(url=curr["resource_url"],
                                               request_data=invalid_resource,
                                               expected_status_code=400,
                                               expected_content_type="application/json")
                    try:
                        self.validator.validate_error(curr["version"], result)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

    def test_post_basic(self):
        """Test POSTing and DELETEing resources"""
        # Check OPTIONS request
        if defines.CHECK_OPTIONS_RESPONSE:
            for curr in self.test_arr:
                self.options_request(url=curr["resource_url"], expected_methods=["OPTIONS", "POST"])

        # POST resources
        for curr in self.test_arr:
            for resource in defines._RESOURCES:
                resource_data = self.sample.get_sample_data(resource=resource, version=curr["version"])
                with self.subTest(url=curr["resource_url"], data=resource_data):
                    response = self.post_request(url=curr["resource_url"],
                                                 request_data=resource_data,
                                                 expected_status_code=201)
                    try:
                        self.validator.validate_resource(resource, curr["version"], response)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

        # RePOSTing should result in 200!
        for curr in self.test_arr:
            for resource in defines._RESOURCES:
                resource_data = self.sample.get_sample_data(resource=resource, version=curr["version"])
                with self.subTest(url=curr["resource_url"], data=resource_data):
                    response = self.post_request(url=curr["resource_url"], request_data=resource_data,
                                                 expected_status_code=200)
                    try:
                        self.validator.validate_resource(resource, curr["version"], response)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

        # # Heartbeats
        for curr in self.test_arr:
            url = "{}{}".format(curr["health_url"],
                                self.sample.get_sample_data(resource="node", version=curr["version"])["data"]["id"])

            # Options
            with self.subTest(url=url):
                expected_methods = ["OPTIONS", "GET", "POST"]
                if defines.CHECK_HEAD_RESPONSE:
                    expected_methods.append("HEAD")
                self.options_request(url=url, expected_methods=expected_methods)

            # POST heartbeat
            self.post_request(url=url,
                              expected_status_code=200,
                              expected_json_response_keys=["health"],
                              expected_content_type="application/json",
                              expected_header_keys=defines.CORS_HEADERS)

            # GET heartbeat
            self.get_request(url=url,
                             expected_status_code=200,
                             expected_json_response_keys=["health"],
                             expected_content_type="application/json",
                             expected_header_keys=defines.CORS_HEADERS)

        # # DELETE resources
        reversed_resource_list = copy.deepcopy(defines._RESOURCES)
        reversed_resource_list.reverse()

        for curr in self.test_arr:
            for resource in reversed_resource_list:
                resource_data = self.sample.get_sample_data(resource=resource, version=curr["version"])
                url = "{}/{}s/{}".format(curr["resource_url"], resource, resource_data["data"]["id"])
                with self.subTest(url=url, id=resource_data["data"]["id"]):
                    self.delete_request(url=url, expected_status_code=204)

        # DELETE non existing resources (already removed!)
        for curr in self.test_arr:
            for resource in reversed_resource_list:
                resource_data = self.sample.get_sample_data(resource=resource, version=curr["version"])
                url = "{}/{}s/{}".format(curr["resource_url"], resource, resource_data["data"]["id"])
                with self.subTest(url=url, id=resource_data["data"]["id"]):
                    result = self.delete_request(url=url,
                                                 expected_status_code=404,
                                                 expected_content_type="application/json")
                    try:
                        self.validator.validate_error(curr["version"], result)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))


class testRegistrationAPINoParent(tools.TestBase):
    """Test posting a "child" resource without it's parent"""

    def setUp(self):
        self.sample = tools.sample_data()
        self.validator = tools.JsonSchemaValidator()

        self.test_arr = [
            {
                "version": v,
                "url": "{}/{}/resource".format(defines._BASE_REGISTRATION_URL, v)
            } for v in defines.VERSIONS
        ]

    def test(self):
        for curr in self.test_arr:
            with self.subTest(url=curr["url"]):
                result = self.post_request(url=curr["url"],
                                           request_data=self.sample.get_sample_data(resource="device",
                                                                                    version=curr["version"]),
                                           expected_status_code=400,
                                           expected_header_keys=defines.CORS_HEADERS,
                                           expected_content_type="application/json")
                try:
                    self.validator.validate_error(curr["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))


class testRegistrationNotHeartbeating(tools.TestBase):
    """Test if all child resources are removed if node not heartbeating
    NOTE: This test is using the QUERY API to verify the deletion of old resources."""

    def setUp(self):
        self.sample = tools.sample_data()
        self.sample.post_sample_data(versions=defines.VERSIONS, resources=defines._RESOURCES)
        self.validator = tools.JsonSchemaValidator()
        self.test_arr = list()
        for version in defines.VERSIONS:
            for resource in defines._RESOURCES:
                self.test_arr.append({"version": version,
                                      "url": "{}/{}/{}s/{}".format(defines._BASE_QUERY_URL,
                                                                   version,
                                                                   resource,
                                                                   self.sample.get_sample_data(resource=resource,
                                                                                               version=version)[
                                                                       "data"]["id"])})

    def test(self):
        # Wait for X seconds in order to let the garbage collection mechanism kick in
        time.sleep(defines.HEARTBEAT_TIMEOUT)
        # Check if all resources are removed
        for curr in self.test_arr:
            with self.subTest(url=curr["url"]):
                # Check GET request
                result = self.get_request(url=curr["url"],
                                          request_headers={"accept": "application/json"},
                                          expected_status_code=404,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json")
                try:
                    self.validator.validate_error(curr["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))


class testRegistrationUncontrolledUnregistering(tools.TestBase):
    """Test uncontrolled unregistration (e.g. node before child-resources)"""

    def setUp(self):
        self.sample = tools.sample_data()
        self.sample.post_sample_data(versions=defines.VERSIONS, resources=defines._RESOURCES)
        self.validator = tools.JsonSchemaValidator()

        for version in defines.VERSIONS:
            # Delete parent node
            self.delete_request(url="{}/{}/resource/nodes/{}".format(defines._BASE_REGISTRATION_URL,
                                                                     version,
                                                                     self.sample.get_sample_data(resource="node",
                                                                                                 version=version)[
                                                                         "data"]["id"]),
                                expected_status_code=204)

        self.test_arr = list()
        for version in defines.VERSIONS:
            for resource in defines._RESOURCES:
                self.test_arr.append({"version": version,
                                      "url": "{}/{}/{}s/{}".format(defines._BASE_QUERY_URL,
                                                                   version,
                                                                   resource,
                                                                   self.sample.get_sample_data(
                                                                       resource=resource,
                                                                       version=version)["data"][
                                                                       "id"])})

    def test(self):
        # Check if all resources are removed
        for curr in self.test_arr:
            with self.subTest(url=curr["url"]):
                # Check GET request
                result = self.get_request(url=curr["url"],
                                          request_headers={"accept": "application/json"},
                                          expected_status_code=404,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json")
                try:
                    self.validator.validate_error(curr["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))
