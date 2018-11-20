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


import defines
import tools


class testAPIBasicRoot(tools.TestBase):
    """Basic tests for the (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/?
        # -----------------------------------------------------------------------------
        self.urls = [
            defines._BASE_URL,
            defines._BASE_URL + "/"
        ]

    def test(self):
        for url in self.urls:
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
                                 expected_json_response_keys=["x-nmos/"])

                # Check GET request with default content-type
                self.get_request(url=url,
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response_keys=["x-nmos/"])


class testAPIBasicXNmos(tools.TestBase):
    """Basic tests for the (REST) API"""

    def setUp(self):
        # -----------------------------------------------------------------------------
        # Test root: <server_proto>://<server_ip>:<server_port>/x-nmos/?
        # -----------------------------------------------------------------------------
        self.urls = [
            defines._BASE_URL + "/x-nmos",
            defines._BASE_URL + "/x-nmos/"
        ]

    def test(self):
        for url in self.urls:
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
                                 expected_json_response=["query/", "registration/"])

                # Check GET request with default content-type
                self.get_request(url=url,
                                 expected_status_code=200,
                                 expected_header_keys=defines.CORS_HEADERS,
                                 expected_content_type="application/json",
                                 expected_json_response=["query/", "registration/"])
