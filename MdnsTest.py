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


from zeroconf import ServiceBrowser, Zeroconf
import time
import ipaddress

import tools
import defines


class MdnsContainer:
    """Container for MDNS announcements"""

    def __init__(self):
        self.service_list = list()

    def add_service(self, zeroconf, type, name):
        """Add a found service to the interal list"""
        self.service_list.append(zeroconf.get_service_info(type, name))

    def get_registration_service(self, ip_address, port):
        """Get the MDNS announcement of the type '_nmos-registration._tcp.local.' with matching IP + PORT"""
        for service in self._get_services(ip_address, port):
            if "_nmos-registration._tcp" in service.type:
                return service
        return None

    def get_query_service(self, ip_address, port):
        """Get the MDNS announcement of the type '_nmos-query._tcp.local.' with matching IP + PORT"""
        for service in self._get_services(ip_address, port):
            if "_nmos-query._tcp" in service.type:
                return service
        return None

    def _get_services(self, ip_address, port):
        """Returns all found services with matching IP and PORT"""
        result = list()
        for service in self.service_list:
            try:
                if str(ipaddress.IPv4Address(service.address)) == ip_address and service.port == port:
                    result.append(service)
            except AttributeError:
                pass
        return result


class testAnnouncements(tools.TestBase):
    """
    Test MDNS announcement
    Searches for mdns announcements of the type '_nmos-registration._tcp.local.' and '_nmos-query._tcp.local.'
    Picks found announcements with matchin SERVER_IP and SERVER_PORT defined in the defines file and checks validity.
    """

    def test(self):
        # Search for services
        container = MdnsContainer()
        zeroconf = Zeroconf()
        reg_browser = ServiceBrowser(zeroconf, "_nmos-registration._tcp.local.", container)
        query_browser = ServiceBrowser(zeroconf, "_nmos-query._tcp.local.", container)
        time.sleep(defines.MDNS_WAIT_TIME)
        reg_browser.cancel()
        query_browser.cancel()
        zeroconf.close()

        # Verify _nmos-registration._tcp announcement
        reg_service = container.get_registration_service(defines.SERVER_IP, defines.SERVER_PORT)
        self.assertIsNotNone(reg_service, msg="No matching service announcement found for '_nmos-registration._tcp'")
        self.evaluate_mdns_announcement(announcement=reg_service,
                                        expected_ip_address=defines.SERVER_IP,
                                        expected_port=defines.SERVER_PORT,
                                        expected_proto=defines.SERVER_PROTO,
                                        expected_type="_nmos-registration._tcp.local.",
                                        expected_versions=",".join(sorted(defines.VERSIONS)))

        # Verify _nmos-query._tcp announcement
        query_service = container.get_query_service(defines.SERVER_IP, defines.SERVER_PORT)
        self.assertIsNotNone(query_service, msg="No matching service announcement found for '_nmos-query._tcp'")
        self.evaluate_mdns_announcement(announcement=query_service,
                                        expected_ip_address=defines.SERVER_IP,
                                        expected_port=defines.SERVER_PORT,
                                        expected_proto=defines.SERVER_PROTO,
                                        expected_type="_nmos-query._tcp.local.",
                                        expected_versions=",".join(sorted(defines.VERSIONS)))
