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


import unittest

import GeneralAPIBasicTest
import QueryServiceTest
import RegistrationServiceTest
import MdnsTest

import defines


def make_suite():
    print("{:*^64}".format("NMOS Registration & Query API test"))
    print("Used configuration:")
    print("{:<48} {}://{}:{}".format("Server address:", defines.SERVER_PROTO, defines.SERVER_IP, defines.SERVER_PORT))
    print("{:<48} {}".format("Testing versions:", str(defines.VERSIONS)))
    print("{:<48}".format("Waiting times:"))
    print("\t{:<48} {}".format("Between HTTP REST API requests:", defines.REQUEST_SLEEP))
    if defines.REQUEST_SLEEP:
        print("\t\t{:<44} {}".format("Amount (s):", str(defines.REQUEST_SLEEP_TIME)))
    print("\t{:<48} {}".format("MDNS Discovery (s):", str(defines.MDNS_WAIT_TIME)))
    print("\t{:<48} {}".format("Garbage Collection kick in (s):", str(defines.HEARTBEAT_TIMEOUT)))
    print("\t{:<48} {}".format("Checking WS messages after opening WS (s):", str(defines.WAIT_WS_OPENING)))
    print("\t{:<48} {}".format("Checking WS messages after changes (s):", str(defines.WAIT_WS_MSG)))
    print("*" * 64)
    print("This might take a while...")

    suite = unittest.TestSuite()

    # ############################## MDNS Announcement Test ##############################
    suite.addTest(unittest.makeSuite(MdnsTest.testAnnouncements))

    # ############################## General REST API Basic tests ##############################
    # REST API (root)
    suite.addTest(unittest.makeSuite(GeneralAPIBasicTest.testAPIBasicRoot))
    # REST API (x-nmos)
    suite.addTest(unittest.makeSuite(GeneralAPIBasicTest.testAPIBasicXNmos))

    # ############################## Registration API Basic tests ##############################
    # REST API (registration-root)
    suite.addTest(unittest.makeSuite(RegistrationServiceTest.testRegistrationAPIBasicRoot))
    # REST API (registration-versions)
    suite.addTest(unittest.makeSuite(RegistrationServiceTest.testRegistrationAPIBasicVersions))
    # REST API (registration-resources)
    suite.addTest(unittest.makeSuite(RegistrationServiceTest.testRegistrationAPIBasicResource))

    # ############################## Registration API Extended tests ##############################
    # Behaviour: Cannot post child resource without known parent
    suite.addTest(unittest.makeSuite(RegistrationServiceTest.testRegistrationAPINoParent))
    # Behaviour: Resources should be garbage collected on missing heartbeats
    suite.addTest(unittest.makeSuite(RegistrationServiceTest.testRegistrationNotHeartbeating))
    # Behaviour: Delete of parent resources should auto-remove their child resources
    suite.addTest(unittest.makeSuite(RegistrationServiceTest.testRegistrationUncontrolledUnregistering))

    # ############################# Query API Basic tests ##############################
    # REST API (query-root)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicRoot))
    # REST API (query-versions)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicVersions))
    # REST API (query-resources-root)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicResourcesRoot))
    # REST API (query-resources-id)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicResourcesId))
    # REST API (query-subscriptions)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicSubscriptionsEndpoint))
    # REST API (query-subscriptions-id)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicSubscriptionsId))
    # REST API (query invalid endpoints)
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryAPIBasicInvalidEndpoints))

    # ############################## Query API Extended tests ##############################
    suite.addTest(unittest.makeSuite(QueryServiceTest.testQueryWebsockets))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(make_suite())
