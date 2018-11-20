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


# Connection data
SERVER_PROTO = "http"
SERVER_IP = "0.0.0.0"
SERVER_PORT = 8888

# Which versions should be tested
VERSIONS = ["v1.2"]

# Default CORS Headers
CORS_HEADERS = ["Access-Control-Allow-Headers",
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Origin"]

# Wait time (s) between each request
REQUEST_SLEEP = False
REQUEST_SLEEP_TIME = 0.005

# Wait time (s) for MDNS announcement search
MDNS_WAIT_TIME = 2.0

# Wait time (s) for garbage collection // missing heartbeat
HEARTBEAT_TIMEOUT = 25.0

# Wait time (s) before checking WS messages after changes
WAIT_WS_MSG = 1.0

# Wait time (s) before checking WS messages after opening
WAIT_WS_OPENING = 0.2

# Check OPTIONS http request
CHECK_OPTIONS_RESPONSE = True

# Check HEAD http request
CHECK_HEAD_RESPONSE = True
# If CHECK_HEAD_RESPONSE is set, define headers explicitly to be checked:
HEAD_COMPARE_HEADERS = [
    "Content-Type",
    "Content-Length",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Origin",
    "Server",
]

# Only check for correct trailing slash handling where required
RELAXED_TRAILING_SLASH_POLICY = False


# # The following parameters should not be modified # #
#  Which resources to test
_RESOURCES = ["node", "device", "sender", "receiver", "source", "flow"]
# Default URL snippets
_BASE_URL = "{}://{}:{}".format(SERVER_PROTO, SERVER_IP, str(SERVER_PORT))
_BASE_XNMOS_URL = _BASE_URL + "/x-nmos"
_BASE_QUERY_URL = _BASE_XNMOS_URL + "/query"
_BASE_REGISTRATION_URL = _BASE_XNMOS_URL + "/registration"
