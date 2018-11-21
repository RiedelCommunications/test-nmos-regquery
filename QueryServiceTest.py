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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import uuid
import json
import time
import copy

import defines
import tools


class testQueryAPIBasicRoot(tools.TestBase):
    """Basic tests for the Query (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/query
        # -----------------------------------------------------------------------------
        self.test_urls = [defines._BASE_QUERY_URL, defines._BASE_QUERY_URL + "/"]

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


class testQueryAPIBasicVersions(tools.TestBase):
    """Testing vX.X endpoints for the Query (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/query/vX.X/?
        # -----------------------------------------------------------------------------
        self.test_urls = ["{}/{}".format(defines._BASE_QUERY_URL, v) for v in defines.VERSIONS]
        self.test_urls.extend(["{}/{}/".format(defines._BASE_QUERY_URL, v) for v in defines.VERSIONS])

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

                expected_json_response = ["{}s/".format(v) for v in defines._RESOURCES]
                expected_json_response.append("subscriptions/")

                # Check GET request
                self.get_request(url=url,
                                 request_headers={"accept": "application/json"},
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response_keys=expected_json_response)

                # Check GET request with default content-type
                self.get_request(url=url,
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response_keys=expected_json_response)


class testQueryAPIBasicResourcesRoot(tools.TestBase):
    """Testing resources root endpoints for the Query (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/query/vX.X/
        #            [nodes|devices|senders|receivers|flows|sources]/?
        # -----------------------------------------------------------------------------
        self.test_arr = list()
        for curr_version in defines.VERSIONS:
            for curr_resource in defines._RESOURCES:
                self.test_arr.append({
                    "url": "{}/{}/{}s".format(defines._BASE_QUERY_URL, curr_version, curr_resource),
                    "resource": curr_resource,
                    "version": curr_version
                })
                self.test_arr.append({
                    "url": "{}/{}/{}s/".format(defines._BASE_QUERY_URL, curr_version, curr_resource),
                    "resource": curr_resource,
                    "version": curr_version
                })
        self.validator = tools.JsonSchemaValidator()

    def test(self):
        for item in self.test_arr:
            with self.subTest(url=item["url"]):
                # Check OPTIONS request
                if defines.CHECK_OPTIONS_RESPONSE:
                    expected_methods = ["OPTIONS", "GET"]
                    if defines.CHECK_HEAD_RESPONSE:
                        expected_methods.append("HEAD")
                    self.options_request(url=item["url"], expected_methods=expected_methods)

                # Check HEAD request
                if defines.CHECK_HEAD_RESPONSE:
                    self.head_request(url=item["url"])

                # Check GET request
                result = self.get_request(url=item["url"],
                                          request_headers={"accept": "application/json"},
                                          expected_status_code=200,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json")

                # Check data validity
                for curr in result:
                    try:
                        self.validator.validate_resource(item["resource"], item["version"], curr)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

                # Check GET request with default content-type
                result = self.get_request(url=item["url"],
                                          expected_status_code=200,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json",
                                          expected_json_response=[])

                for curr in result:
                    try:
                        self.validator.validate_resource(item["resource"], item["version"], curr)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))


class testQueryAPIBasicResourcesId(tools.TestBase):
    """Testing resources id endpoints for the Query (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/query/vX.X/
        #            [nodes|devices|senders|receivers|flows|sources]/<id>/?
        # -----------------------------------------------------------------------------

        self.sample = tools.sample_data()
        self.sample.post_sample_data(versions=defines.VERSIONS, resources=defines._RESOURCES)

        self.test_arr = list()
        for version in defines.VERSIONS:
            for resource in defines._RESOURCES:
                self.test_arr.append({"url": "{}/{}/{}s/{}".format(defines._BASE_QUERY_URL,
                                                                   version,
                                                                   resource,
                                                                   self.sample.get_sample_data(resource=resource,
                                                                                               version=version)[
                                                                       "data"][
                                                                       "id"]),
                                      "version": version,
                                      "resource": resource})
                self.test_arr.append({"url": "{}/{}/{}s/{}/".format(defines._BASE_QUERY_URL,
                                                                    version,
                                                                    resource,
                                                                    self.sample.get_sample_data(resource=resource,
                                                                                                version=version)[
                                                                        "data"][
                                                                        "id"]),
                                      "version": version,
                                      "resource": resource})
        self.validator = tools.JsonSchemaValidator()

    def test(self):
        for item in self.test_arr:
            with self.subTest(url=item["url"]):
                # Extract UUID for easy comparison
                url_parts = item["url"].split("/")
                curr_id = url_parts[len(url_parts) - 1]

                # Check OPTIONS request
                if defines.CHECK_OPTIONS_RESPONSE:
                    expected_methods = ["OPTIONS", "GET"]
                    if defines.CHECK_HEAD_RESPONSE:
                        expected_methods.append("HEAD")
                    self.options_request(url=item["url"], expected_methods=expected_methods)

                # Check HEAD request
                if defines.CHECK_HEAD_RESPONSE:
                    self.head_request(url=item["url"])

                # Check GET request
                result = self.get_request(url=item["url"],
                                          request_headers={"accept": "application/json"},
                                          expected_status_code=200,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json",
                                          expected_json_response=self.sample.get_sample_resource_by_id(curr_id))

                try:
                    self.validator.validate_resource(item["resource"], item["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))

                # Check GET request with default content-type
                result = self.get_request(url=item["url"],
                                          expected_status_code=200,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json",
                                          expected_json_response=self.sample.get_sample_resource_by_id(curr_id))

                try:
                    self.validator.validate_resource(item["resource"], item["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))

    def tearDown(self):
        self.sample.remove_sample_data(check_result=False, versions=defines.VERSIONS)


class testQueryAPIBasicSubscriptionsEndpoint(tools.TestBase):
    """Testing subscriptions root endpoints for the Query (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/query/vX.X/
        #            [subscriptions]/?
        # -----------------------------------------------------------------------------
        self.test_arr = list()
        for version in defines.VERSIONS:
            self.test_arr.append({
                "url": "{}/{}/subscriptions".format(defines._BASE_QUERY_URL, version),
                "version": version
            })
            self.test_arr.append({
                "url": "{}/{}/subscriptions/".format(defines._BASE_QUERY_URL, version),
                "version": version
            })
        self.validator = tools.JsonSchemaValidator()

    def test(self):
        for item in self.test_arr:
            with self.subTest(url=item["url"]):
                # Check OPTIONS request
                if defines.CHECK_OPTIONS_RESPONSE:
                    expected_methods = ["OPTIONS", "GET", "POST"]
                    if defines.CHECK_HEAD_RESPONSE:
                        expected_methods.append("HEAD")
                    self.options_request(url=item["url"], expected_methods=expected_methods)

                # Check HEAD request
                if defines.CHECK_HEAD_RESPONSE:
                    self.head_request(url=item["url"])

                # Check GET request
                result = self.get_request(url=item["url"],
                                          request_headers={"accept": "application/json"},
                                          expected_status_code=200,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json")

                for curr in result:
                    try:
                        self.validator.validate_resource("subscription", item["version"], curr)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

                # Check GET request with default content-type
                result = self.get_request(url=item["url"],
                                          expected_status_code=200,
                                          expected_header_keys=defines.CORS_HEADERS,
                                          expected_content_type="application/json")

                for curr in result:
                    try:
                        self.validator.validate_resource("subscription", item["version"], curr)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))


class testQueryAPIBasicSubscriptionsId(tools.TestBase):
    """Tests POST & DELETE subscriptions"""

    def setUp(self):
        """Post subscription"""

        self.test_arr = list()
        for version in defines.VERSIONS:
            self.test_arr.append({
                "url": "{}/{}/subscriptions".format(defines._BASE_QUERY_URL, version),
                "version": version
            })
        self.sample = tools.sample_data()
        self.valid_sub_request_data = self.sample._get_valid_subscription_data()
        self.valid_sub_request_data_persist = copy.deepcopy(self.sample._get_valid_subscription_data())
        self.valid_sub_request_data_persist["persist"] = True

        self.invalid_sub_request_data = copy.deepcopy(self.valid_sub_request_data)
        del self.invalid_sub_request_data["resource_path"]

        self.validator = tools.JsonSchemaValidator()

    def test_valid_sub_request(self):
        for item in self.test_arr:
            with self.subTest(url=item["url"]):
                # Check OPTIONS request
                if defines.CHECK_OPTIONS_RESPONSE:
                    expected_methods = ["OPTIONS", "GET", "POST"]
                    if defines.CHECK_HEAD_RESPONSE:
                        expected_methods.append("HEAD")
                    self.options_request(url=item["url"], expected_methods=expected_methods)

                # Check HEAD request
                if defines.CHECK_HEAD_RESPONSE:
                    self.head_request(url=item["url"])

                # Check POST request
                response = self.post_request(url=item["url"],
                                             request_headers={"accept": "application/json"},
                                             request_data=self.valid_sub_request_data,
                                             expected_header_keys=defines.CORS_HEADERS,
                                             expected_content_type="application/json",
                                             expected_json_response_subset=self.valid_sub_request_data)

                try:
                    self.validator.validate_resource("subscription", item["version"], response)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))

                # Check GET of previously posted sub
                sub_id = response["id"]

                url = copy.copy(item["url"])
                if url[-1] != "/":
                    url += "/"

                new_test_urls = [url + sub_id, url + sub_id + "/"]

                for new_test_url in new_test_urls:
                    with self.subTest(url=new_test_url):
                        # Check OPTIONS request
                        if defines.CHECK_OPTIONS_RESPONSE:
                            expected_methods = ["OPTIONS", "GET", "DELETE"]
                            if defines.CHECK_HEAD_RESPONSE:
                                expected_methods.append("HEAD")
                            self.options_request(url=new_test_url, expected_methods=expected_methods)

                        # Check HEAD request
                        if defines.CHECK_HEAD_RESPONSE:
                            self.head_request(url=new_test_url)

                        # Check GET request
                        response1 = self.get_request(url=new_test_url,
                                                     request_headers={"accept": "application/json"},
                                                     expected_status_code=200,
                                                     expected_header_keys=defines.CORS_HEADERS,
                                                     expected_content_type="application/json",
                                                     expected_json_response=response)

                        try:
                            self.validator.validate_resource("subscription", item["version"], response1)
                        except tools.jsonschema.ValidationError as e:
                            self.fail(str(e))

                        # Check GET request with default content-type
                        response2 = self.get_request(url=new_test_url,
                                                     expected_status_code=200,
                                                     expected_header_keys=defines.CORS_HEADERS,
                                                     expected_content_type="application/json",
                                                     expected_json_response=response)

                        try:
                            self.validator.validate_resource("subscription", item["version"], response2)
                        except tools.jsonschema.ValidationError as e:
                            self.fail(str(e))

                # Re-requesting same Subscription request should return 200 now!
                with self.subTest(url=item["url"]):
                    response = self.post_request(url=item["url"],
                                                 request_headers={"accept": "application/json"},
                                                 request_data=self.valid_sub_request_data,
                                                 expected_status_code=200,
                                                 expected_header_keys=defines.CORS_HEADERS,
                                                 expected_content_type="application/json",
                                                 expected_json_response=response)
                    try:
                        self.validator.validate_resource("subscription", item["version"], response)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

                # # Check DELETE of sub
                # NOTE: non-persistent subscriptions should be managed by the server
                # itself, and may not be deleted externally!
                with self.subTest(url=new_test_urls[0]):
                    result = self.delete_request(new_test_urls[0],
                                                 expected_status_code=403,
                                                 expected_content_type="application/json")
                    try:
                        self.validator.validate_error(item["version"], result)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

                # Requesting Subscription with persist = True
                response = self.post_request(url=item["url"],
                                             request_headers={"accept": "application/json"},
                                             request_data=self.valid_sub_request_data_persist,
                                             expected_header_keys=defines.CORS_HEADERS,
                                             expected_content_type="application/json")

                try:
                    self.validator.validate_resource("subscription", item["version"], response)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))

                # Check GET of previously posted sub
                sub_id = response["id"]
                url = copy.copy(item["url"])
                if url[-1] != "/":
                    url += "/"

                new_test_urls = [url + sub_id, url + sub_id + "/"]

                # Check DELETE of persistent sub
                with self.subTest(url=new_test_urls[0]):
                    self.delete_request(new_test_urls[0],
                                        expected_status_code=204)

                # Check DELETED of non existent resource
                with self.subTest(url=new_test_urls[0]):
                    result = self.delete_request(new_test_urls[0],
                                                 expected_status_code=404,
                                                 expected_content_type="application/json")
                    try:
                        self.validator.validate_error(item["version"], result)
                    except tools.jsonschema.ValidationError as e:
                        self.fail(str(e))

    def test_invalid_sub_request(self):
        for item in self.test_arr:
            with self.subTest(url=item["url"]):
                result = self.post_request(url=item["url"],
                                           request_headers={"accept": "application/json"},
                                           request_data=self.invalid_sub_request_data,
                                           expected_status_code=400,
                                           expected_header_keys=defines.CORS_HEADERS,
                                           expected_content_type="application/json")
                try:
                    self.validator.validate_error(item["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))


class testQueryAPIBasicInvalidEndpoints(tools.TestBase):
    """Basic tests for the Query (REST) API - checks for correct error handling on non existing resources"""

    def setUp(self):
        random_id = str(uuid.uuid4())
        self.validator = tools.JsonSchemaValidator()

        self.invalid_test_arr = [
            {"version": "v1.0", "url": "{}a".format(defines._BASE_QUERY_URL)},
            {"version": "v1.0", "url": "{}/x1.0".format(defines._BASE_QUERY_URL)}
        ]
        res = copy.deepcopy(defines._RESOURCES)
        res.append("subscription")
        for v in defines.VERSIONS:
            for r in res:
                self.invalid_test_arr.append({"version": v, "url": "{}/{}/{}".format(defines._BASE_QUERY_URL, v, r)})
                self.invalid_test_arr.append(
                    {"version": v, "url": "{}/{}/{}s/{}".format(defines._BASE_QUERY_URL, v, r, random_id)})
                self.invalid_test_arr.append(
                    {"version": v, "url": "{}/{}/{}s/{}/".format(defines._BASE_QUERY_URL, v, r, random_id)})

    def test(self):
        for curr in self.invalid_test_arr:
            with self.subTest(url=curr["url"]):
                # Check GET request
                result = self.get_request(url=curr["url"],
                                          request_headers={"accept": "application/json"},
                                          expected_status_code=404,
                                          expected_content_type="application/json")
                try:
                    self.validator.validate_error(curr["version"], result)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))


class testQueryWebsockets(tools.TestBase):
    """Test Websockets"""

    def setUp(self):
        self.sample = tools.sample_data()
        self.json_validator = tools.JsonSchemaValidator()

        # Request Data for Sub / Nodes
        sub_data_base = {
            "max_update_rate_ms": 100,
            "resource_path": "",
            "params": {},
            "persist": False,
            "secure": False
        }
        self.test_items = list()

        for curr_version in defines.VERSIONS:
            for curr_resource in ["/{}s".format(v) for v in defines._RESOURCES]:
                sub_data = sub_data_base
                sub_data["resource_path"] = curr_resource

                # Request ws_href
                response = self.post_request(url="{}/{}/subscriptions".format(defines._BASE_QUERY_URL,
                                                                              curr_version),
                                             request_headers={"accept": "application/json"},
                                             request_data=sub_data)

                try:
                    self.json_validator.validate_subscription(curr_version, response)
                except tools.jsonschema.ValidationError as e:
                    self.fail(str(e))

                # Setup WS Client worker
                ws_client = tools.WSWorker(response["ws_href"])

                expected_data = self.sample.get_sample_data(resource=curr_resource.replace("/", "")[:-1],
                                                            version=curr_version)
                expected_data_updated = copy.deepcopy(expected_data)
                expected_data_updated["data"]["label"] = expected_data_updated["data"]["label"] + "_updated"
                self.sample.bump_resource_version(expected_data_updated)

                test_item = {
                    "ws_href": response["ws_href"],
                    "expected_data": expected_data,
                    "expected_data_updated": expected_data_updated,
                    "version": curr_version,
                    "resource": curr_resource,
                    "ws_client": ws_client
                }
                self.test_items.append(test_item)

    def test(self):
        # Post sample data
        self.sample.post_sample_data(versions=defines.VERSIONS, resources=defines._RESOURCES)
        time.sleep(defines.WAIT_WS_MSG)

        # Test Sync messages
        for i in range(0, len(self.test_items)):
            with self.subTest(type="Sync-check",
                              resource=self.test_items[i]["resource"],
                              version=self.test_items[i]["version"]):

                self.test_items[i]["ws_client"].start()

                time.sleep(defines.WAIT_WS_OPENING)

                self.assertFalse(self.test_items[i]["ws_client"].did_error_occur(),
                                 msg=self.test_items[i]["ws_client"].get_error_message())

                received_messages = self.test_items[i]["ws_client"].get_messages()

                # -- Verify data inside messages --
                grain_data = list()
                for curr_msg in received_messages:
                    try:
                        json_msg = json.loads(curr_msg)

                        # Verify message format
                        try:
                            version = self.test_items[i]["version"]
                            self.json_validator.validate_subscription_websocket(version, json_msg)
                        except tools.jsonschema.ValidationError as e:
                            self.fail(str(e))

                        # Verify topic
                        self.assertIn(self.test_items[i]["resource"], json_msg["grain"]["topic"],
                                      msg="Topic of ẃebsocket message does not match")

                        grain_data.extend(json_msg["grain"]["data"])

                    except json.decoder.JSONDecodeError as e:
                        self.fail("Failed to read json out of websocket message: {}".format(str(e)))

                # Search for the expected data
                found_data_set = False
                for curr_data in grain_data:
                    try:
                        if self._ordered(curr_data["pre"]) == \
                                self._ordered(self.test_items[i]["expected_data"]["data"]):
                            if self._ordered(curr_data["post"]) == \
                                    self._ordered(self.test_items[i]["expected_data"]["data"]):
                                found_data_set = True
                    except KeyError as e:
                        self.fail(msg=str(e))

                self.assertTrue(found_data_set, msg="Did not found expected data set in websocket messages.")

        # Update sample data
        self.sample.update_sample_data(versions=defines.VERSIONS, resources=defines._RESOURCES)
        time.sleep(defines.WAIT_WS_MSG)

        # Test Update messages
        for i in range(0, len(self.test_items)):
            with self.subTest(type="Update-check",
                              resource=self.test_items[i]["resource"],
                              version=self.test_items[i]["version"]):

                received_messages = self.test_items[i]["ws_client"].get_messages()

                # -- Verify data inside messages --
                grain_data = list()
                for curr_msg in received_messages:
                    try:
                        json_msg = json.loads(curr_msg)

                        # Verify message format
                        try:
                            version = self.test_items[i]["version"]
                            self.json_validator.validate_subscription_websocket(version, json_msg)
                        except tools.jsonschema.ValidationError as e:
                            self.fail(str(e))

                        # Verify topic
                        self.assertIn(self.test_items[i]["resource"], json_msg["grain"]["topic"],
                                      msg="Topic of websocket message does not match")

                        grain_data.extend(json_msg["grain"]["data"])

                    except json.decoder.JSONDecodeError as e:
                        self.fail("Failed to read json out of websocket message: {}".format(str(e)))

                # Search for the expected data
                found_data_set = False
                for curr_data in grain_data:
                    try:
                        if self._ordered(curr_data["pre"]) == \
                                self._ordered(self.test_items[i]["expected_data"]["data"]):
                            if self._ordered(curr_data["post"]) == \
                                    self._ordered(self.test_items[i]["expected_data_updated"]["data"]):
                                found_data_set = True
                    except KeyError as e:
                        self.fail(msg=str(e))

                self.assertTrue(found_data_set, msg="Did not found expected data set in websocket messages.")

        # Remove resources
        self.sample.remove_sample_data(versions=defines.VERSIONS)
        time.sleep(defines.WAIT_WS_MSG)

        for i in range(0, len(self.test_items)):
            with self.subTest(type="Remove check",
                              resource=self.test_items[i]["resource"],
                              version=self.test_items[i]["version"]):

                received_messages = self.test_items[i]["ws_client"].get_messages()

                # -- Verify data inside messages --
                grain_data = list()
                for curr_msg in received_messages:
                    try:
                        json_msg = json.loads(curr_msg)

                        # Verify message format
                        try:
                            version = self.test_items[i]["version"]
                            self.json_validator.validate_subscription_websocket(version, json_msg)
                        except tools.jsonschema.ValidationError as e:
                            self.fail(str(e))

                        # Verify topic
                        self.assertIn(self.test_items[i]["resource"], json_msg["grain"]["topic"],
                                      msg="Topic of websocket message does not match")

                        grain_data.extend(json_msg["grain"]["data"])

                    except json.decoder.JSONDecodeError as e:
                        self.fail("Failed to read json out of websocket message: {}".format(str(e)))

                # Search for the expected data
                found_data_set = False
                for curr_data in grain_data:
                    try:
                        if self._ordered(curr_data["pre"]) == \
                                self._ordered(self.test_items[i]["expected_data_updated"]["data"]):
                            if "post" not in curr_data:
                                found_data_set = True
                    except KeyError as e:
                        self.fail(msg=str(e))

                self.assertTrue(found_data_set, msg="Did not found expected data set in websocket messages.")

    def tearDown(self):
        for item in self.test_items:
            if "ws_client" in item:
                item["ws_client"].close()
        self.sample.remove_sample_data(check_result=False, versions=defines.VERSIONS)
