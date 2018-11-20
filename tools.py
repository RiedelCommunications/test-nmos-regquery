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


import os
import json
import unittest
import requests
import time
import ipaddress
import websocket
import jsonschema
import threading
import copy

import defines


class TestBase(unittest.TestCase):
    """Collection of basic HTTP Request tests & helper functions as base class to inherit further tests"""

    def options_request(self, url="", request_headers=None, expected_methods=None):
        """
        HTTP OPTIONS REQUEST
        :param url: endpoint url (string)
        :param expected_methods: expected methods which are allowed on the endpoint (list of strings)
        :param request_headers: additional request headers (dict) for the request
        :return: -
        """
        if defines.RELAXED_TRAILING_SLASH_POLICY:
            if url.endswith("/"):  # Skip (only 'SHOULD')
                return

        # Wait before sending next request
        if defines.REQUEST_SLEEP:
            time.sleep(defines.REQUEST_SLEEP_TIME)

        # Request
        r = requests.options(url, headers=request_headers)

        # Status code
        self.assertEqual(200, r.status_code, msg="OPTIONS response does not have correct status_code")

        # Expected methods allowed
        self.assertIn("Allow", r.headers)
        for expected_method in expected_methods:
            self.assertIn(expected_method, r.headers["Allow"], msg="OPTIONS response did not contain expected method")

    def head_request(self, url="", request_headers=None):
        """
        HTTP HEAD REQUEST
        :param url: endpoint url (string)
        :param request_headers: additional request headers (dict) for the request
        :return: -
        """
        # Wait before sending next request
        if defines.REQUEST_SLEEP:
            time.sleep(defines.REQUEST_SLEEP_TIME)

        # Make GET request
        r_get = requests.get(url, headers=request_headers)

        # Make HEAD request
        r_head = requests.head(url, headers=request_headers)

        # Compare
        for h in defines.HEAD_COMPARE_HEADERS:
            if h in r_get.headers and h in r_head.headers:
                self.assertEqual(self._ordered(r_get.headers[h]), self._ordered(r_head.headers[h]),
                                 msg="HEAD header differs from GET header.")

    def get_request(self,
                    url="",
                    request_headers=None,
                    expected_status_code=0,
                    expected_header_keys=None,
                    expected_content_type="",
                    expected_json_response=None,
                    expected_json_response_subset=None,
                    expected_json_in_list=None,
                    expected_json_response_keys=None):
        """
        HTTP GET REQUEST
        :param url: endpoint url (string)
        :param request_headers: additional request headers (dict) for the request
        :param expected_status_code: expected return status code (int)
        :param expected_header_keys: expected header keys (list)
        :param expected_content_type: expected content type (string)
        :param expected_json_response: expected json response (dict)
        :param expected_json_response_subset: expected json subset (dict)
        :param expected_json_in_list: expected json in list (dict)
        :param expected_json_response_keys: expected json keys in response (list)
        :return: returned json or None
        """
        # Wait before sending next request
        if defines.REQUEST_SLEEP:
            time.sleep(defines.REQUEST_SLEEP_TIME)

        # Request
        r = requests.get(url, headers=request_headers)

        # Status code
        if expected_status_code:
            self.assertEqual(expected_status_code, r.status_code, msg="Returned unexpected status code")

        # Header keys
        if expected_header_keys:
            for key in expected_header_keys:
                self.assertIn(key, r.headers, msg="Response did not contain expected header: {}".format(key))

        # Content-type
        if expected_content_type:
            self.assertIn(expected_content_type, r.headers['content-type'],
                          msg="Response does not have expected content-type")

        # Verify message length
        if "content-length" in r.headers:
            self.assertIn("content-length", r.headers, msg="Response does not contain 'content-length' header")
            self.assertEqual(len(r.text), int(r.headers["content-length"]),
                             msg="Content length does not match value in 'content-length' header")

        # JSON response
        if expected_json_response:
            self.assertEqual(self._ordered(expected_json_response), self._ordered(r.json()),
                             msg="Response does not contain expected JSON")
        if expected_json_response_subset:
            for sub in expected_json_response_subset:
                for key in sub.keys():
                    self.assertEqual(sub[key], r.json()[key], msg="Response JSON does not contain expected value")
        if expected_json_response_keys:
            for key in expected_json_response_keys:
                self.assertIn(key, r.json(), msg="Response JSON does not contain expected key")
        if expected_json_in_list:
            self.assertIn(self._ordered(expected_json_in_list), [self._ordered(v) for v in r.json()],
                          msg="Expected JSON not in list")
        try:
            return r.json()
        except json.decoder.JSONDecodeError:
            return None

    def post_request(self,
                     url="",
                     request_headers=None,
                     request_data=None,
                     expected_status_code=0,
                     expected_header_keys=None,
                     expected_content_type="",
                     expected_json_response=None,
                     expected_json_response_subset=None,
                     expected_json_response_keys=None):
        """
        HTTP POST REQUEST
        :param url: endpoint url (string)
        :param request_headers: additional request headers (dict) for the request
        :param request_data: data to send with the request (json)
        :param expected_status_code: expected return status code (int)
        :param expected_header_keys: expected header keys (list)
        :param expected_content_type: expected content type (string)
        :param expected_json_response: expected json response (dict)
        :param expected_json_response_subset: expected json subset (dict)
        :param expected_json_response_keys: expected json keys in response (list)
        :return: returned json or None
        """

        if defines.RELAXED_TRAILING_SLASH_POLICY:
            if url.endswith("/"):  # Skip (only 'SHOULD')
                return

        # Wait before sending next request
        if defines.REQUEST_SLEEP:
            time.sleep(defines.REQUEST_SLEEP_TIME)

        # Request
        r = requests.post(url, headers=request_headers, data=json.dumps(request_data))

        # Status code
        if expected_status_code:
            self.assertEqual(expected_status_code, r.status_code, msg="Returned unexpected status code")

        # Header keys
        if expected_header_keys:
            for key in expected_header_keys:
                self.assertIn(key, r.headers, msg="Response did not contain expected header: {}".format(key))

        # Content-type
        if expected_content_type:
            self.assertIn(expected_content_type, r.headers['content-type'],
                          msg="Response does not have expected content-type")

        # Verify message length
        if "content-length" in r.headers:
            self.assertIn("content-length", r.headers, msg="Response does not contain 'content-length' header")
            self.assertEqual(len(r.text), int(r.headers["content-length"]),
                             msg="Content length does not match value in 'content-length' header")

        # JSON response
        if expected_json_response:
            self.assertEqual(self._ordered(expected_json_response), self._ordered(r.json()),
                             msg="Response does not contain expected JSON")
        if expected_json_response_subset:
            for key in expected_json_response_subset.keys():
                self.assertEqual(expected_json_response_subset[key], r.json()[key],
                                 msg="Response JSON does not contain expected value")
        if expected_json_response_keys:
            for key in expected_json_response_keys:
                self.assertIn(key, r.json(), msg="Response JSON does not contain expected key")

        try:
            return r.json()
        except json.decoder.JSONDecodeError:
            return None

    def delete_request(self,
                       url="",
                       request_headers=None,
                       expected_status_code=0,
                       expected_header_keys=None,
                       expected_content_type="",
                       expected_json_response=None,
                       expected_json_response_subset=None,
                       expected_json_response_keys=None):
        """
        HTTP DELETE REQUEST
        :param url: endpoint url (string)
        :param request_headers: additional request headers (dict) for the request
        :param expected_status_code: expected return status code (int)
        :param expected_header_keys: expected header keys (list)
        :param expected_content_type: expected content type (string)
        :param expected_json_response: expected json response (dict)
        :param expected_json_response_subset: expected json subset (dict)
        :param expected_json_response_keys: expected json keys in response (list)
        :return: returned json or None
        """

        if defines.RELAXED_TRAILING_SLASH_POLICY:
            if url.endswith("/"):  # Skip (only 'SHOULD')
                return

        # Wait before sending next request
        if defines.REQUEST_SLEEP:
            time.sleep(defines.REQUEST_SLEEP_TIME)

        # Request
        r = requests.delete(url, headers=request_headers)

        # Status code
        if expected_status_code:
            self.assertEqual(expected_status_code, r.status_code, msg="Returned unexpected status code")

        # Header keys
        if expected_header_keys:
            for key in expected_header_keys:
                self.assertIn(key, r.headers, msg="Response did not contain expected header: {}".format(key))

        # Content-type
        if expected_content_type:
            self.assertIn(expected_content_type, r.headers['content-type'],
                          msg="Response does not have expected content-type")

        # JSON response
        if expected_json_response:
            self.assertEqual(self._ordered(expected_json_response), self._ordered(r.json()),
                             msg="Response does not contain expected JSON")
        if expected_json_response_subset:
            for sub in expected_json_response_subset:
                for key in sub.keys():
                    self.assertEqual(sub[key], r.json()[key], msg="Response JSON does not contain expected value")
        if expected_json_response_keys:
            for key in expected_json_response_keys:
                self.assertIn(key, r.json(), msg="Response JSON does not contain expected key")

        try:
            return r.json()
        except json.decoder.JSONDecodeError:
            return None

    def evaluate_mdns_announcement(self,
                                   announcement=None,
                                   expected_ip_address="",
                                   expected_port=0,
                                   expected_versions=None,
                                   expected_proto=None,
                                   expected_type=""):
        """
        Evaluate MDNS announcement
        :param announcement: mdns announcement (zeroconf obj)
        :param expected_ip_address: expected ip address inside mdns announcement (string)
        :param expected_port: expected port inside mdns announcement (int)
        :param expected_versions: expected versions inside mdns announcement (string)
        :param expected_proto: expected proto inside mdns announcement (string)
        :param expected_type: expected type inside mdns announcement (string)
        :return: -
        """
        # Type
        self.assertEqual(expected_type, announcement.type, msg="Expected type does not match")
        # Address
        self.assertEqual(expected_ip_address, str(ipaddress.IPv4Address(announcement.address)),
                         msg="Expected ip address does not match")
        # Port
        self.assertEqual(expected_port, announcement.port, msg="Expected port does not match")

        # Extract properties
        props = announcement.properties

        # Decode data
        props_decoded = {k.decode("utf-8"): v.decode("utf-8") for k, v in props.items()}

        # Versions
        self.assertIn(expected_versions, props_decoded["api_ver"], msg="Expected versions not found in announcement")

        # Proto
        self.assertIn(expected_proto, props_decoded["api_proto"], msg="Expected proto not found in announcement")

    def _ordered(self, obj):
        """Helperfunction: Sort JSON obj/arr for JSON comparison"""
        if isinstance(obj, dict):
            return sorted((k, self._ordered(v)) for k, v in obj.items())
        if isinstance(obj, list):
            return sorted(self._ordered(x) for x in obj)
        else:
            return obj


class sample_data:
    """Helper class which loads and manages sample data"""
    def __init__(self):
        self.sample_data_v10 = self._load_valid_sample_data_v10()
        self.sample_data_v11 = self._load_valid_sample_data_v11()
        self.sample_data_v12 = self._load_valid_sample_data_v12()
        self.sample_subscription_data = self._load_valid_subscription_example()
        self.util = TestBase()

    def post_sample_data(self, versions, resources):
        """Post sample resources of the given version"""
        for version in versions:
            for resource in resources:
                url = "{}/{}/resource".format(defines._BASE_REGISTRATION_URL, version)
                data = self.get_sample_data(resource, version)
                self.util.post_request(url=url,
                                       request_data=data,
                                       expected_status_code=201,
                                       expected_json_response=data["data"])

    def update_sample_data(self, versions, resources):
        """Update sample resources of the given version"""
        for version in versions:
            for resource in resources:
                url = "{}/{}/resource".format(defines._BASE_REGISTRATION_URL, version)
                data = copy.deepcopy(self.get_sample_data(resource=resource, version=version))
                data["data"]["label"] = data["data"]["label"] + "_updated"
                self.util.post_request(url=url,
                                       request_data=data,
                                       expected_status_code=200,
                                       expected_json_response=data["data"])

    def get_sample_resource_by_id(self, uuid):
        """Returns the sample resource with the given id"""
        for item in self._get_valid_sample_data_v10() + \
                    self._get_valid_sample_data_v11() + \
                    self._get_valid_sample_data_v12():
            if item["data"]["id"] == uuid:
                return item["data"]
        return None

    def remove_sample_data(self, check_result=True, versions=None):
        """Remove nodes of the given version (Registry should remove child resources automatically)"""
        for version in versions:
            if check_result:
                self.util.delete_request(url="{}/{}/resource/nodes/{}".format(defines._BASE_REGISTRATION_URL,
                                                                              version,
                                                                              self.get_sample_data("node", version)[
                                                                                  "data"][
                                                                                  "id"]),
                                         expected_status_code=204)
            else:
                self.util.delete_request(url="{}/{}/resource/nodes/{}".format(defines._BASE_REGISTRATION_URL,
                                                                              version,
                                                                              self.get_sample_data("node", version)[
                                                                                  "data"][
                                                                                  "id"]))

    def get_sample_data(self, resource, version):
        """Get sample data in format: {"type": <type>, "data": <data>}"""
        if resource == "node":
            if version == "v1.0":
                return self._get_sample_node_v10()
            elif version == "v1.1":
                return self._get_sample_node_v11()
            elif version == "v1.2":
                return self._get_sample_node_v12()
        elif resource == "device":
            if version == "v1.0":
                return self._get_sample_device_v10()
            elif version == "v1.1":
                return self._get_sample_device_v11()
            elif version == "v1.2":
                return self._get_sample_device_v12()
        elif resource == "sender":
            if version == "v1.0":
                return self._get_sample_sender_v10()
            elif version == "v1.1":
                return self._get_sample_sender_v11()
            elif version == "v1.2":
                return self._get_sample_sender_v12()
        elif resource == "receiver":
            if version == "v1.0":
                return self._get_sample_receiver_v10()
            elif version == "v1.1":
                return self._get_sample_receiver_v11()
            elif version == "v1.2":
                return self._get_sample_receiver_v12()
        elif resource == "source":
            if version == "v1.0":
                return self._get_sample_source_v10()
            elif version == "v1.1":
                return self._get_sample_source_v11()
            elif version == "v1.2":
                return self._get_sample_source_v12()
        elif resource == "flow":
            if version == "v1.0":
                return self._get_sample_flow_v10()
            elif version == "v1.1":
                return self._get_sample_flow_v11()
            elif version == "v1.2":
                return self._get_sample_flow_v12()
        return None

    def _get_valid_sample_data_v10(self):
        return self.sample_data_v10

    def _get_sample_node_v10(self):
        return self.sample_data_v10[0]

    def _get_sample_device_v10(self):
        return self.sample_data_v10[1]

    def _get_sample_sender_v10(self):
        return self.sample_data_v10[2]

    def _get_sample_receiver_v10(self):
        return self.sample_data_v10[3]

    def _get_sample_source_v10(self):
        return self.sample_data_v10[4]

    def _get_sample_flow_v10(self):
        return self.sample_data_v10[5]

    def _get_valid_sample_data_v11(self):
        return self.sample_data_v11

    def _get_sample_node_v11(self):
        return self.sample_data_v11[0]

    def _get_sample_device_v11(self):
        return self.sample_data_v11[1]

    def _get_sample_sender_v11(self):
        return self.sample_data_v11[2]

    def _get_sample_receiver_v11(self):
        return self.sample_data_v11[3]

    def _get_sample_source_v11(self):
        return self.sample_data_v11[4]

    def _get_sample_flow_v11(self):
        return self.sample_data_v11[5]

    def _get_valid_sample_data_v12(self):
        return self.sample_data_v12

    def _get_sample_node_v12(self):
        return self.sample_data_v12[0]

    def _get_sample_device_v12(self):
        return self.sample_data_v12[1]

    def _get_sample_sender_v12(self):
        return self.sample_data_v12[2]

    def _get_sample_receiver_v12(self):
        return self.sample_data_v12[3]

    def _get_sample_source_v12(self):
        return self.sample_data_v12[4]

    def _get_sample_flow_v12(self):
        return self.sample_data_v12[5]

    def _get_valid_subscription_data(self):
        return self.sample_subscription_data

    def _load_valid_sample_data_v10(self):
        """
        Loads (valid) sample data in v1.0
        Resultarray in order: node, device, sender, receiver, source, flow
        """
        project_dir = os.path.dirname(os.path.realpath('__file__'))

        file_v10_node = open(os.path.join(project_dir, "json/example_resources/example__v1.0__node.json"))
        json_v10_node = json.load(file_v10_node)
        file_v10_node.close()

        file_v10_device = open(os.path.join(project_dir, "json/example_resources/example__v1.0__device.json"))
        json_v10_device = json.load(file_v10_device)
        file_v10_device.close()

        file_v10_sender = open(os.path.join(project_dir, "json/example_resources/example__v1.0__sender.json"))
        json_v10_sender = json.load(file_v10_sender)
        file_v10_sender.close()

        file_v10_receiver = open(
            os.path.join(project_dir, "json/example_resources/example__v1.0__receiver.json"))
        json_v10_receiver = json.load(file_v10_receiver)
        file_v10_receiver.close()

        file_v10_source = open(os.path.join(project_dir, "json/example_resources/example__v1.0__source.json"))
        json_v10_source = json.load(file_v10_source)
        file_v10_source.close()

        file_v10_flow = open(os.path.join(project_dir, "json/example_resources/example__v1.0__flow.json"))
        json_v10_flow = json.load(file_v10_flow)
        file_v10_flow.close()

        post_data_arr_v10 = list()
        post_data_arr_v10.append(json_v10_node)
        post_data_arr_v10.append(json_v10_device)
        post_data_arr_v10.append(json_v10_sender)
        post_data_arr_v10.append(json_v10_receiver)
        post_data_arr_v10.append(json_v10_source)
        post_data_arr_v10.append(json_v10_flow)

        return post_data_arr_v10

    def _load_valid_sample_data_v11(self):
        """
        Loads (valid) sample data in v1.1
        Resultarray in order: node, device, sender, receiver, source, flow
        """
        project_dir = os.path.dirname(os.path.realpath('__file__'))

        file_v11_node = open(os.path.join(project_dir, "json/example_resources/example__v1.1__node.json"))
        json_v11_node = json.load(file_v11_node)
        file_v11_node.close()

        file_v11_device = open(os.path.join(project_dir, "json/example_resources/example__v1.1__device.json"))
        json_v11_device = json.load(file_v11_device)
        file_v11_device.close()

        file_v11_sender = open(os.path.join(project_dir, "json/example_resources/example__v1.1__sender.json"))
        json_v11_sender = json.load(file_v11_sender)
        file_v11_sender.close()

        file_v11_receiver = open(
            os.path.join(project_dir, "json/example_resources/example__v1.1__receiver.json"))
        json_v11_receiver = json.load(file_v11_receiver)
        file_v11_receiver.close()

        file_v11_source = open(os.path.join(project_dir, "json/example_resources/example__v1.1__source.json"))
        json_v11_source = json.load(file_v11_source)
        file_v11_source.close()

        file_v11_flow = open(os.path.join(project_dir, "json/example_resources/example__v1.1__flow.json"))
        json_v11_flow = json.load(file_v11_flow)
        file_v11_flow.close()

        post_data_arr_v11 = list()
        post_data_arr_v11.append(json_v11_node)
        post_data_arr_v11.append(json_v11_device)
        post_data_arr_v11.append(json_v11_sender)
        post_data_arr_v11.append(json_v11_receiver)
        post_data_arr_v11.append(json_v11_source)
        post_data_arr_v11.append(json_v11_flow)

        return post_data_arr_v11

    def _load_valid_sample_data_v12(self):
        """
        Loads (valid) sample data in v1.2
        Resultarray in order: node, device, sender, receiver, source, flow
        """
        project_dir = os.path.dirname(os.path.realpath('__file__'))

        file_v12_node = open(os.path.join(project_dir, "json/example_resources/example__v1.2__node.json"))
        json_v12_node = json.load(file_v12_node)
        file_v12_node.close()

        file_v12_device = open(os.path.join(project_dir, "json/example_resources/example__v1.2__device.json"))
        json_v12_device = json.load(file_v12_device)
        file_v12_device.close()

        file_v12_sender = open(os.path.join(project_dir, "json/example_resources/example__v1.2__sender.json"))
        json_v12_sender = json.load(file_v12_sender)
        file_v12_sender.close()

        file_v12_receiver = open(
            os.path.join(project_dir, "json/example_resources/example__v1.2__receiver.json"))
        json_v12_receiver = json.load(file_v12_receiver)
        file_v12_receiver.close()

        file_v12_source = open(os.path.join(project_dir, "json/example_resources/example__v1.2__source.json"))
        json_v12_source = json.load(file_v12_source)
        file_v12_source.close()

        file_v12_flow = open(os.path.join(project_dir, "json/example_resources/example__v1.2__flow.json"))
        json_v12_flow = json.load(file_v12_flow)
        file_v12_flow.close()

        post_data_arr_v12 = list()
        post_data_arr_v12.append(json_v12_node)
        post_data_arr_v12.append(json_v12_device)
        post_data_arr_v12.append(json_v12_sender)
        post_data_arr_v12.append(json_v12_receiver)
        post_data_arr_v12.append(json_v12_source)
        post_data_arr_v12.append(json_v12_flow)

        return post_data_arr_v12

    def _load_valid_subscription_example(self):
        """
        Loads (valid) sample data
        """
        project_dir = os.path.dirname(os.path.realpath('__file__'))

        file_sub = open(os.path.join(project_dir, "json/example_resources/example_post_subscription.json"))
        json_sub = json.load(file_sub)
        file_sub.close()

        return json_sub


class WSWorker(threading.Thread):
    """Websocket Client Worker Thread"""

    def __init__(self, ws_href):
        """
        Initializer
        :param ws_href: websocket url (string)
        """
        threading.Thread.__init__(self)
        self.ws_href = ws_href
        self.ws = websocket.WebSocketApp(ws_href,
                                         on_message=self.on_message,
                                         on_close=self.on_close,
                                         on_open=self.on_open,
                                         on_error=self.on_error)
        self.messages = list()
        self.error_occured = False
        self.error_message = ""

    def run(self):
        self.ws.run_forever()

    def on_open(self):
        pass

    def on_message(self, message):
        self.messages.append(message)

    def on_close(self):
        pass

    def on_error(self, error):
        self.error_occured = True
        self.error_message = error

    def close(self):
        self.ws.close()

    def get_messages(self):
        msg_cpy = copy.copy(self.messages)
        self.clear_messages()  # Reset message list after reading
        return msg_cpy

    def did_error_occur(self):
        return self.error_occured

    def get_error_message(self):
        return self.error_message

    def clear_messages(self):
        self.messages.clear()


class JsonSchemaValidator():
    """Validates given JSON against the schemas
    Surround function calls with TRY/EXCEPT block to catch errors:

    use:
            except jsonschema.ValidationError as e:
            for validation errors (content + structural errors in json)
    use:
            except Exception as e:
            for all general + internal errors (e.g.: couldn't open schema file)

    Functions do not return anything, just execute and catch for errors. On success, nothing will happen.
    """
    def __init__(self):
        # Open & store validation files
        self.file_v10_node = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.0", "node.json"))
        self.json_v10_node = json.load(self.file_v10_node)
        self.file_v10_node.close()
        self.file_v10_device = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.0", "device.json"))
        self.json_v10_device = json.load(self.file_v10_device)
        self.file_v10_device.close()
        self.file_v10_sender = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.0", "sender.json"))
        self.json_v10_sender = json.load(self.file_v10_sender)
        self.file_v10_sender.close()
        self.file_v10_receiver = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.0", "receiver.json"))
        self.json_v10_receiver = json.load(self.file_v10_receiver)
        self.file_v10_receiver.close()
        self.file_v10_flow = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.0", "flow.json"))
        self.json_v10_flow = json.load(self.file_v10_flow)
        self.file_v10_flow.close()
        self.file_v10_source = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.0", "source.json"))
        self.json_v10_source = json.load(self.file_v10_source)
        self.file_v10_source.close()
        self.file_v10_subscription = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.0", "queryapi-v1.0-subscriptions-post-request.json"))
        self.json_v10_subscription = json.load(self.file_v10_subscription)
        self.file_v10_subscription.close()
        self.file_v10_subscription_websocket = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.0", "queryapi-v1.0-subscriptions-websocket.json"))
        self.json_v10_subscription_websocket = json.load(self.file_v10_subscription_websocket)
        self.file_v10_subscription_websocket.close()
        self.file_v10_error = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.0", "error.json"))
        self.json_v10_error = json.load(self.file_v10_error)
        self.file_v10_error.close()
        # v1.1
        self.file_v11_node = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.1", "node.json"))
        self.json_v11_node = json.load(self.file_v11_node)
        self.file_v11_node.close()
        self.file_v11_device = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.1", "device.json"))
        self.json_v11_device = json.load(self.file_v11_device)
        self.file_v11_device.close()
        self.file_v11_sender = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.1", "sender.json"))
        self.json_v11_sender = json.load(self.file_v11_sender)
        self.file_v11_sender.close()
        self.file_v11_receiver = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.1", "receiver.json"))
        self.json_v11_receiver = json.load(self.file_v11_receiver)
        self.file_v11_receiver.close()
        self.file_v11_flow = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.1", "flow.json"))
        self.json_v11_flow = json.load(self.file_v11_flow)
        self.file_v11_flow.close()
        self.file_v11_source = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.1", "source.json"))
        self.json_v11_source = json.load(self.file_v11_source)
        self.file_v11_source.close()
        self.file_v11_subscription = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.1", "queryapi-subscriptions-post-request.json"))
        self.json_v11_subscription = json.load(self.file_v11_subscription)
        self.file_v11_subscription.close()
        self.file_v11_subscription_websocket = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.1", "queryapi-subscriptions-websocket.json"))
        self.json_v11_subscription_websocket = json.load(self.file_v11_subscription_websocket)
        self.file_v11_subscription_websocket.close()
        self.file_v11_error = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.1", "error.json"))
        self.json_v11_error = json.load(self.file_v11_error)
        self.file_v11_error.close()
        # v1.2
        self.file_v12_node = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.2", "node.json"))
        self.json_v12_node = json.load(self.file_v12_node)
        self.file_v12_node.close()
        self.file_v12_device = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.2", "device.json"))
        self.json_v12_device = json.load(self.file_v12_device)
        self.file_v12_device.close()
        self.file_v12_sender = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.2", "sender.json"))
        self.json_v12_sender = json.load(self.file_v12_sender)
        self.file_v12_sender.close()
        self.file_v12_receiver = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.2", "receiver.json"))
        self.json_v12_receiver = json.load(self.file_v12_receiver)
        self.file_v12_receiver.close()
        self.file_v12_flow = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.2", "flow.json"))
        self.json_v12_flow = json.load(self.file_v12_flow)
        self.file_v12_flow.close()
        self.file_v12_source = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')), "json", "schema", "v1.2", "source.json"))
        self.json_v12_source = json.load(self.file_v12_source)
        self.file_v12_source.close()
        self.file_v12_subscription = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.2", "queryapi-subscriptions-post-request.json"))
        self.json_v12_subscription = json.load(self.file_v12_subscription)
        self.file_v12_subscription.close()
        self.file_v12_subscription_websocket = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.2", "queryapi-subscriptions-websocket.json"))
        self.json_v12_subscription_websocket = json.load(self.file_v12_subscription_websocket)
        self.file_v12_subscription_websocket.close()
        self.file_v12_error = open(
            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                         "json", "schema", "v1.2", "error.json"))
        self.json_v12_error = json.load(self.file_v12_error)
        self.file_v12_error.close()

        # Resolve relative '$refs' in schemas
        # v1.0
        self.node_v10_resolver = jsonschema.RefResolver("file:///" +
                                                        os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                     "json", "schema", "v1.0") + "/",
                                                        self.json_v10_node)

        self.device_v10_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.0") + "/",
                                                          self.json_v10_device)

        self.sender_v10_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.0") + "/",
                                                          self.json_v10_sender)

        self.receiver_v10_resolver = jsonschema.RefResolver("file:///" +
                                                            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                         "json", "schema", "v1.0") + "/",
                                                            self.json_v10_receiver)

        self.flow_v10_resolver = jsonschema.RefResolver("file:///" +
                                                        os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                     "json", "schema", "v1.0") + "/",
                                                        self.json_v10_flow)

        self.source_v10_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.0") + "/",
                                                          self.json_v10_source)

        self.subscription_v10_resolver = jsonschema.RefResolver("file:///" +
                                                                os.path.join(
                                                                    os.path.dirname(os.path.realpath('__file__')),
                                                                    "json", "schema", "v1.0") + "/",
                                                                self.json_v10_subscription)
        self.subscription_websocket_v10_resolver = jsonschema.RefResolver("file:///" +
                                                                          os.path.join(
                                                                              os.path.dirname(
                                                                                  os.path.realpath('__file__')),
                                                                              "json", "schema", "v1.0") + "/",
                                                                          self.json_v10_subscription_websocket)
        self.error_v10_resolver = jsonschema.RefResolver("file:///" +
                                                                          os.path.join(
                                                                              os.path.dirname(
                                                                                  os.path.realpath('__file__')),
                                                                              "json", "schema", "v1.0") + "/",
                                                                          self.json_v10_error)
        # v1.1
        self.node_v11_resolver = jsonschema.RefResolver("file:///" +
                                                        os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                     "json", "schema", "v1.1") + "/",
                                                        self.json_v11_node)

        self.device_v11_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.1") + "/",
                                                          self.json_v11_device)

        self.sender_v11_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.1") + "/",
                                                          self.json_v11_sender)

        self.receiver_v11_resolver = jsonschema.RefResolver("file:///" +
                                                            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                         "json", "schema", "v1.1") + "/",
                                                            self.json_v11_receiver)

        self.flow_v11_resolver = jsonschema.RefResolver("file:///" +
                                                        os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                     "json", "schema", "v1.1") + "/",
                                                        self.json_v11_flow)

        self.source_v11_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.1") + "/",
                                                          self.json_v11_source)

        self.subscription_v11_resolver = jsonschema.RefResolver("file:///" +
                                                                os.path.join(
                                                                    os.path.dirname(os.path.realpath('__file__')),
                                                                    "json", "schema", "v1.1") + "/",
                                                                self.json_v11_subscription)
        self.subscription_websocket_v11_resolver = jsonschema.RefResolver("file:///" +
                                                                          os.path.join(
                                                                              os.path.dirname(
                                                                                  os.path.realpath('__file__')),
                                                                              "json", "schema", "v1.1") + "/",
                                                                          self.json_v11_subscription_websocket)
        self.error_v11_resolver = jsonschema.RefResolver("file:///" +
                                                                          os.path.join(
                                                                              os.path.dirname(
                                                                                  os.path.realpath('__file__')),
                                                                              "json", "schema", "v1.1") + "/",
                                                                          self.json_v11_error)
        # v1.2
        self.node_v12_resolver = jsonschema.RefResolver("file:///" +
                                                        os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                     "json", "schema", "v1.2") + "/",
                                                        self.json_v12_node)

        self.device_v12_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.2") + "/",
                                                          self.json_v12_device)

        self.sender_v12_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.2") + "/",
                                                          self.json_v12_sender)

        self.receiver_v12_resolver = jsonschema.RefResolver("file:///" +
                                                            os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                         "json", "schema", "v1.2") + "/",
                                                            self.json_v12_receiver)

        self.flow_v12_resolver = jsonschema.RefResolver("file:///" +
                                                        os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                     "json", "schema", "v1.2") + "/",
                                                        self.json_v12_flow)

        self.source_v12_resolver = jsonschema.RefResolver("file:///" +
                                                          os.path.join(os.path.dirname(os.path.realpath('__file__')),
                                                                       "json", "schema", "v1.2") + "/",
                                                          self.json_v12_source)

        self.subscription_v12_resolver = jsonschema.RefResolver("file:///" +
                                                                os.path.join(
                                                                    os.path.dirname(os.path.realpath('__file__')),
                                                                    "json", "schema", "v1.2") + "/",
                                                                self.json_v12_subscription)
        self.subscription_websocket_v12_resolver = jsonschema.RefResolver("file:///" +
                                                                          os.path.join(
                                                                              os.path.dirname(
                                                                                  os.path.realpath('__file__')),
                                                                              "json", "schema", "v1.2") + "/",
                                                                          self.json_v12_subscription_websocket)
        self.error_v12_resolver = jsonschema.RefResolver("file:///" +
                                                                          os.path.join(
                                                                              os.path.dirname(
                                                                                  os.path.realpath('__file__')),
                                                                              "json", "schema", "v1.2") + "/",
                                                                          self.json_v12_error)

    def validate_resource(self, resource, version, data):
        """Validate 'resource' json against schema"""
        if resource == "node":
            self.validate_node(version, data)
        elif resource == "device":
            self.validate_device(version, data)
        elif resource == "sender":
            self.validate_sender(version, data)
        elif resource == "receiver":
            self.validate_receiver(version, data)
        elif resource == "source":
            self.validate_source(version, data)
        elif resource == "flow":
            self.validate_flow(version, data)
        elif resource == "subscription":
            self.validate_subscription(version, data)
        else:
            print("Error: Unknown resource: {}".format(resource))

    def validate_node(self, version, data):
        """Validate node json against node schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_node, resolver=self.node_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_node, resolver=self.node_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_node, resolver=self.node_v12_resolver).validate(data)
            else:
                raise jsonschema.ValidationError("{}".format("Unexpected error. Unknown version '{}'".format(version)))
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_device(self, version, data):
        """Validate device json against device schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_device, resolver=self.device_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_device, resolver=self.device_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_device, resolver=self.device_v12_resolver).validate(data)
            else:
                raise jsonschema.ValidationError("{}".format("Unexpected error. Unknown version '{}'".format(version)))
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_sender(self, version, data):
        """Validate sender json against sender schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_sender, resolver=self.sender_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_sender, resolver=self.sender_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_sender, resolver=self.sender_v12_resolver).validate(data)
            else:
                raise jsonschema.ValidationError("{}".format("Unexpected error. Unknown version '{}'".format(version)))
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_receiver(self, version, data):
        """Validate receiver json against receiver schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_receiver, resolver=self.receiver_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_receiver, resolver=self.receiver_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_receiver, resolver=self.receiver_v12_resolver).validate(data)
            else:
                raise jsonschema.ValidationError("{}".format("Unexpected error. Unknown version '{}'".format(version)))
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_flow(self, version, data):
        """Validate flow json against flow schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_flow, resolver=self.flow_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_flow, resolver=self.flow_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_flow, resolver=self.flow_v12_resolver).validate(data)
            else:
                raise jsonschema.ValidationError("{}".format("Unexpected error. Unknown version '{}'".format(version)))
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_source(self, version, data):
        """Validate source json against source schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_source, resolver=self.source_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_source, resolver=self.source_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_source, resolver=self.source_v12_resolver).validate(data)
            else:
                raise jsonschema.ValidationError("{}".format("Unexpected error. Unknown version '{}'".format(version)))
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_subscription(self, version, data):
        """Validate subscription json against subscription schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_subscription,
                                           resolver=self.subscription_v10_resolver).validate(
                    data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_subscription,
                                           resolver=self.subscription_v11_resolver).validate(
                    data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_subscription,
                                           resolver=self.subscription_v12_resolver).validate(data)
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_subscription_websocket(self, version, data):
        """Validate subscription response json against subscription schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_subscription_websocket,
                                           resolver=self.subscription_websocket_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_subscription_websocket,
                                           resolver=self.subscription_websocket_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_subscription_websocket,
                                           resolver=self.subscription_websocket_v12_resolver).validate(data)
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise

    def validate_error(self, version, data):
        """Validate error response json against schema"""
        try:
            if version == "v1.0":
                jsonschema.Draft4Validator(self.json_v10_error,
                                           resolver=self.error_v10_resolver).validate(data)
            elif version == "v1.1":
                jsonschema.Draft4Validator(self.json_v11_error,
                                           resolver=self.error_v11_resolver).validate(data)
            elif version == "v1.2":
                jsonschema.Draft4Validator(self.json_v12_error,
                                           resolver=self.error_v12_resolver).validate(data)
        except jsonschema.ValidationError as e:
            # Cut off superfluous info from validation errors.
            error_string = str(e)
            error_message = error_string.split("\n\n")
            if len(error_message) >= 1:
                raise jsonschema.ValidationError("{}".format(error_message[0]))
            else:
                raise