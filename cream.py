"""
Class to configure Cisco ISE via the ERS API
"""
import inspect
import json
import logging
import math
import os
import re
import requests
from furl import furl

logger = logging.getLogger(__name__)

base_dir = os.path.dirname(__file__)


class InvalidMacAddress(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ERS:
    def __init__(
        self,
        ise_uri,
        ers_user,
        ers_pass,
        verify=False,
        disable_warnings=False,
        timeout=2,
    ):  # pylint: disable=too-many-arguments
        """
        Class to interact with Cisco ISE via the ERS API
        :param ise_uri: ERS URI including protocol and port
        :param ers_user: ERS username
        :param ers_pass: ERS password
        :param verify: Verify SSL cert
        :param disable_warnings: Disable requests warnings
        :param timeout: Query timeout
        """
        self.user_name = ers_user
        self.user_pass = ers_pass

        self.url_base = "{0}/ers".format(ise_uri)
        self.ise = requests.session()
        self.ise.auth = (self.user_name, self.user_pass)
        # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.ise.verify = verify
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.ise.headers.update({"Connection": "keep_alive"})

        if self.disable_warnings:
            requests.packages.urllib3.disable_warnings()

    def close(self):
        self.ise.close()

    @staticmethod
    def _mac_test(mac):
        """
        Test for valid mac address
        :param mac: MAC address in the form of AA:BB:CC:00:11:22
        :return: True/False
        """

        if re.search(r"([0-9A-F]{2}[:]){5}([0-9A-F]){2}", mac.upper()) is not None:
            return True

        return False

    @staticmethod
    def _pass_ersresponse(result, resp):
        module = __name__ + "." + inspect.currentframe().f_code.co_name
        logger.info("%s: Uh oh, we have an error: %s", module, resp.json())

        result["response"] = resp.json()["ERSResponse"]["messages"][0]["title"]
        result["error"] = resp.status_code
        return result

    def _method_get(self, url, ers_filter: str = None, size: int = 100, page: int = 1, res_all=True):
        # pylint: disable=too-many-arguments, unused-argument
        """
        Generic GET method for accessing the ISE API
        :param url: Base URL for requesting lists
        :param ers_filter: argument side of a ERS filter string. Default: None
        :param size: size of the page to return. Default: 100
        :param page: page to return. Default: 1
        :param res_all: do we want all results, not just this page. Default: True
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        result = {"success": False, "response": [], "error": ""}
        logger.info("%s: Retrieving page: %s. %s items per page", module, page, size)

        # https://github.com/gruns/furl
        f = furl(url)
        f.args["page"] = page

        # Test for valid size 1<=x>=100
        if 1 <= size <= 100:
            f.args["size"] = size
        else:
            # Not in range, use the default 100
            f.args["size"] = 100

        # TODO add filter validation
        if ers_filter:
            f.args["filter"] = ers_filter

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        logger.info("%s: Calling ise.get with url: %s", module, f.url)
        resp = self.ise.get(f.url)
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())

        logger.info("%s: Status: %s", module, resp.status_code)
        if resp.status_code == 200:
            result["success"] = True
            # Append the results to the response list
            for i in resp.json()["SearchResult"]["resources"]:
                description = i.get("description", "")
                result["response"].append([i["name"], i["id"], description])
            # Check for multiple pages.
            total = int(resp.json()["SearchResult"]["total"])
            lastpage = math.ceil(total / size)
            if (total > size) and (page < lastpage):
                logger.debug(
                    "%s: We have more pages - This Page: %s, Total Pages: %s, Total Records: %s",
                    module,
                    page,
                    lastpage,
                    total,
                )
                # Recurse to get the next page.
                logger.info("%s: Calling _method_get for page: %s", module, page + 1)
                innerresult = self._method_get(url=url, ers_filter=ers_filter, size=size, page=page + 1, res_all=True)
                if innerresult["success"]:
                    # Success, add the returned results to ours
                    for i in innerresult["response"]:
                        result["response"].append([i[0], i[1], i[2]])
                else:
                    # error retrieving the next page, fail the whole tree.
                    result = innerresult
            return result

        return ERS._pass_ersresponse(result, resp)

    def get_endpoint_groups(self):
        """
        Get all endpoint identity groups
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        logger.info("%s: Calling _method_get", module)
        return self._method_get("{0}/config/endpointgroup".format(self.url_base))

    def get_endpoint_group(self, group=False, pk=False):
        """
        Get endpoint identity group details
        :param pk: id of identity group
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        if group:
            logger.debug("%s: Group is set, I want group by name: %s", module, group)

            logger.info("%s: Calling ise.get with group: %s", module, group)
            resp = self.ise.get("{0}/config/endpointgroup?filter=name.EQ.{1}".format(self.url_base, group))
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
            found_group = resp.json()

            if found_group["SearchResult"]["total"] == 1:
                pk = found_group["SearchResult"]["resources"][0]["id"]

        if pk:
            logger.debug("%s: PK is set, I want group by ID: %s", module, pk)

            logger.info("%s: Calling ise.get with pk: %s", module, pk)
            resp = self.ise.get("{0}/config/endpointgroup/{1}".format(self.url_base, pk))
            if resp.status_code != 200:
                result["response"] = "Error..."
                result["error"] = resp.status_code
                return result

            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
            result["success"] = True
            result["response"] = resp.json()["EndPointGroup"]
            return result

        logger.info("%s: No PK set, return 404.", module)
        result["response"] = "Error..."
        result["error"] = resp.status_code
        return ERS._pass_ersresponse(result, resp)

    def update_endpoint_group(self, group_id, name="", description=""):
        """
        Update endpoint details
        :param id: ISE GUID of the endpoint group
        :param name: Name of the endpoint group
        :param description: Description of the endpoint group
        :return: result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}

        data = {"ERSEndPoint": {"id": group_id, "name": name, "description": description}}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        logger.info("%s: Calling ise.put with group: %s, data: %s", module, group_id, data)
        resp = self.ise.put(
            "{0}/config/endpointgroup/{1}".format(self.url_base, group_id),
            data=json.dumps(data),
            timeout=self.timeout,
        )
        logger.info("%s: Raw response received from ISE: %s", module, resp.json())
        if resp.status_code == 200:
            # TODO: use resp.json()['UpdatedFieldsList']
            jsonresp = json.loads(resp.text)
            result["success"] = True
            result["response"] = jsonresp["UpdatedFieldsList"]
            return result

        return ERS._pass_ersresponse(result, resp)

    def get_endpoints(self, group=None):
        """
        Get all endpoints
        :param group: Name of the identity group
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        if group is None:
            logger.info("%s: Calling _method_get", module)
            return self._method_get("{0}/config/endpoint".format(self.url_base))

        logger.info("%s: Calling _method_get with group: %s", module, group)
        return self._method_get(
            "{0}/config/endpoint".format(self.url_base),
            ers_filter="groupId.EQ.{0}".format(group),
        )

    def get_endpoint(self, mac_address):
        """
        Get endpoint details
        :param mac_address: MAC address of the endpoint
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac_address)
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        if not is_valid:
            raise InvalidMacAddress("{0}. Must be in the form of AA:BB:CC:00:11:22".format(mac_address))

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}

        logger.info("%s: Calling ise.get with MAC: %s", module, mac_address)
        resp = self.ise.get("{0}/config/endpoint?filter=mac.EQ.{1}".format(self.url_base, mac_address))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        found_endpoint = resp.json()

        if found_endpoint["SearchResult"]["total"] == 1:
            logger.info(
                "%s: Calling ise.get with ID: %s",
                module,
                found_endpoint["SearchResult"]["resources"][0]["id"],
            )
            resp = self.ise.get(
                "{0}/config/endpoint/{1}".format(
                    self.url_base,
                    found_endpoint["SearchResult"]["resources"][0]["id"],
                )
            )
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
            if resp.status_code == 200:
                result["success"] = True
                result["response"] = resp.json()["ERSEndPoint"]
                return result

            if resp.status_code == 404:
                result["response"] = "{0} not found".format(mac_address)
                result["error"] = resp.status_code
                return result

            return ERS._pass_ersresponse(result, resp)

        if found_endpoint["SearchResult"]["total"] == 0:
            result["response"] = "{0} not found".format(mac_address)
            result["error"] = 404
            return result

        result["response"] = "{0} not found".format(mac_address)
        result["error"] = resp.status_code
        return result

    def add_endpoint(
        self,
        name,
        mac,
        group_id,
        static_profile_assigment="false",
        static_group_assignment="true",
        profile_id="",
        description="",
    ):  # pylint: disable=too-many-arguments
        """
        Add a user to the local user store
        :param name: Name
        :param mac: Macaddress
        :param group_id: OID of group to add endpoint in
        :param static_profile_assigment: Set static profile
        :param static_group_assignment: Set static group
        :param profile_id: OID of profile
        :param description: User description
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac)
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        if not is_valid:
            raise InvalidMacAddress("{0}. Must be in the form of AA:BB:CC:00:11:22".format(mac))

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}

        data = {
            "ERSEndPoint": {
                "name": name,
                "description": description,
                "mac": mac,
                "profileId": profile_id,
                "staticProfileAssignment": static_profile_assigment,
                "groupId": group_id,
                "staticGroupAssignment": static_group_assignment,
                "customAttributes": {"customAttributes": {"key1": "value1"}},
            }
        }

        logger.info("%s: Calling ise.post with data: %s", module, json.dumps(data))
        resp = self.ise.post(
            "{0}/config/endpoint".format(self.url_base),
            data=json.dumps(data),
            timeout=self.timeout,
        )
        logger.info("%s: Raw response returned from ISE: %s", module, resp)
        if resp.status_code == 201:
            result["success"] = True
            result["response"] = "{0} Added Successfully".format(name)
            return result

        return ERS._pass_ersresponse(result, resp)

    def update_endpoint(
        self,
        endpoint_id,
        name,
        mac,
        group_id,
        static_profile_assigment="false",
        static_group_assignment="true",
        profile_id="",
        description="",
    ):  # pylint: disable=too-many-arguments
        """
        Modify an endpoint in the ISE database
        :param endpoint_id: OID of the endpoint
        :param name: Name
        :param mac: Macaddress
        :param group_id: OID of group to add endpoint in
        :param static_profile_assigment: Set static profile
        :param static_group_assignment: Set static group
        :param profile_id: OID of profile
        :param description: User description
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac)
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        if not is_valid:
            raise InvalidMacAddress("{0}. Must be in the form of AA:BB:CC:00:11:22".format(mac))

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}

        data = {
            "ERSEndPoint": {
                "id": endpoint_id,
                "name": name,
                "description": description,
                "mac": mac,
                "profileId": profile_id,
                "staticProfileAssignment": static_profile_assigment,
                "groupId": group_id,
                "staticGroupAssignment": static_group_assignment,
                "customAttributes": {"customAttributes": {"key1": "value1"}},
            }
        }

        logger.info("%s: Calling ise.put with data: %s", module, json.dumps(data))
        resp = self.ise.put(
            "{0}/config/endpoint/{1}".format(self.url_base, endpoint_id),
            data=json.dumps(data),
            timeout=self.timeout,
        )
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        if resp.status_code == 200:
            result["success"] = True
            result["response"] = resp.json()["UpdatedFieldsList"]
            return result

        return ERS._pass_ersresponse(result, resp)

    def delete_endpoint(self, mac=None, endpoint_id=None):
        """
        Delete an endpoint
        :param mac: Endpoint Macaddress
        :return: Result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        # if ID is blank lets go find it.
        if not endpoint_id:
            logger.debug("%s: ID is not set, lets see if we have a MAC address", module)
            if not mac:
                # uh, oh. no mac, cant continue
                logger.debug("%s: No ID or MAC, we can't continue", module)
                result["description"] = "Input error, delete could not be processed."
                return result

            # lets find the ID from the MAC
            logger.info("%s: Calling get_endpoint with MAC: %s", module, mac)
            result = self.get_endpoint(mac)
            endpoint_id = result["response"]["0"]["id"]

        logger.info("%s: Calling ise.delete with endpoint_id: %s", module, endpoint_id)
        resp = self.ise.delete(
            "{0}/config/endpoint/{1}".format(self.url_base, endpoint_id),
            timeout=self.timeout,
        )
        logger.info("%s: Raw response returned from ISE: %s", module, resp)

        if resp.status_code == 204:
            result["success"] = True
            result["response"] = "{0} Deleted Successfully".format(mac)
            return result

        if resp.status_code == 404:
            result["response"] = "{0} not found".format(mac)
            result["error"] = resp.status_code
            return result

        return ERS._pass_ersresponse(result, resp)

    def get_identity_groups(self):
        """
        Get all identity groups
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        logger.info("%s: Calling _method_get", module)
        return self._method_get("{0}/config/identitygroup".format(self.url_base))

    def get_identity_group(self, group):
        """
        Get identity group details
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        logger.info("%s: Calling ise.get with group: %s", module, group)
        resp = self.ise.get("{0}/config/identitygroup?filter=name.EQ.{1}".format(self.url_base, group))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        found_group = resp.json()

        if found_group["SearchResult"]["total"] == 1:
            resp = self.ise.get(
                "{0}/config/identitygroup/{1}".format(self.url_base, found_group["SearchResult"]["resources"][0]["id"])
            )
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
            if resp.status_code == 200:
                result["success"] = True
                result["response"] = resp.json()["IdentityGroup"]
                return result

            if resp.status_code == 404:
                result["response"] = "{0} not found".format(group)
                result["error"] = resp.status_code
                return result

            return ERS._pass_ersresponse(result, resp)

        if found_group["SearchResult"]["total"] == 0:
            result["response"] = "{0} not found".format(group)
            result["error"] = 404
            return result

        result["response"] = "{0} not found".format(group)
        result["error"] = resp.status_code
        return result

    def get_users(self):
        """
        Get all internal users
        :return: List of tuples of user details
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        logger.info("%s: Calling _method_get", module)
        return self._method_get("{0}/config/internaluser".format(self.url_base))

    def get_user(self, user_id):
        """
        Get user detailed info
        :param user_id: User ID
        :return: result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        logger.info("%s: Calling ise.get with user: %s", module, user_id)
        resp = self.ise.get("{0}/config/internaluser?filter=name.EQ.{1}".format(self.url_base, user_id))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        found_user = resp.json()

        if found_user["SearchResult"]["total"] == 1:
            logger.info(
                "%s: Calling ise.get with user id: %s",
                module,
                found_user["SearchResult"]["resources"][0]["id"],
            )
            resp = self.ise.get(
                "{0}/config/internaluser/{1}".format(self.url_base, found_user["SearchResult"]["resources"][0]["id"])
            )
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
            if resp.status_code == 200:
                result["success"] = True
                result["response"] = resp.json()["InternalUser"]
                return result

            if resp.status_code == 404:
                result["response"] = "{0} not found".format(user_id)
                result["error"] = resp.status_code
                return result

            return ERS._pass_ersresponse(result, resp)

        if found_user["SearchResult"]["total"] == 0:
            result["response"] = "{0} not found".format(user_id)
            result["error"] = 404
            return result

        result["response"] = "Unknown error"
        result["error"] = resp.status_code
        return result

    def add_user(
        self,
        user_id,
        password,
        user_group_oid,
        enable="",
        first_name="",
        last_name="",
        email="",
        description="",
    ):  # pylint: disable=too-many-arguments
        """
        Add a user to the local user store
        :param user_id: User ID
        :param password: User password
        :param user_group_oid: OID of group to add user to
        :param enable: Enable password used for Tacacs
        :param first_name: First name
        :param last_name: Last name
        :param email: email address
        :param description: User description
        :return: result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        data = {
            "InternalUser": {
                "name": user_id,
                "password": password,
                "enablePassword": enable,
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "description": description,
                "identityGroups": user_group_oid,
            }
        }

        logger.info("%s: Calling ise.post with data: %s", module, data.json())
        resp = self.ise.post(
            "{0}/config/internaluser".format(self.url_base),
            data=json.dumps(data),
            timeout=self.timeout,
        )
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        if resp.status_code == 201:
            result["success"] = True
            result["response"] = "{0} Added Successfully".format(user_id)
            return result

        return ERS._pass_ersresponse(result, resp)

    def delete_user(self, user_id):
        """
        Delete a user
        :param user_id: User ID
        :return: Result dictionary
        """
        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        result = {"success": False, "response": "", "error": ""}
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name

        logger.info("%s: Calling ise.get with user: %s", module, user_id)
        resp = self.ise.get("{0}/config/internaluser?filter=name.EQ.{1}".format(self.url_base, user_id))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        found_user = resp.json()

        if found_user["SearchResult"]["total"] == 1:
            user_oid = found_user["SearchResult"]["resources"][0]["id"]
            logger.info("%s: Calling ise.delete with user_id: %s", module, user_oid)
            resp = self.ise.delete(
                "{0}/config/internaluser/{1}".format(self.url_base, user_oid),
                timeout=self.timeout,
            )
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())

            if resp.status_code == 204:
                result["success"] = True
                result["response"] = "{0} Deleted Successfully".format(user_id)
                return result

            if resp.status_code == 404:
                result["response"] = "{0} not found".format(user_id)
                result["error"] = resp.status_code
                return result

            return ERS._pass_ersresponse(result, resp)

        if found_user["SearchResult"]["total"] == 0:
            result["response"] = "{0} not found".format(user_id)
            result["error"] = 404
            return result

        return ERS._pass_ersresponse(result, resp)

    def get_device_groups(self):
        """
        Get a list tuples of device groups
        :return:
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        logger.info("%s: Calling _method_get", module)
        return self._method_get("{0}/config/networkdevicegroup".format(self.url_base))

    def get_device_group(self, device_group_oid):
        """
        Get a device group details
        :param device_group_oid: oid of the device group
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        result = {"success": False, "response": "", "error": ""}

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        logger.info("%s: Calling ise.get with networkdevicegroup: %s", module, device_group_oid)
        resp = self.ise.get("{0}/config/networkdevicegroup/{1}".format(self.url_base, device_group_oid))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())

        if resp.status_code == 200:
            result["success"] = True
            result["response"] = resp.json()["NetworkDeviceGroup"]
            return result

        if resp.status_code == 404:
            result["response"] = "{0} not found".format(device_group_oid)
            result["error"] = resp.status_code
            return result

        return ERS._pass_ersresponse(result, resp)

    def get_devices(self):
        """
        Get a list of devices
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        logger.info("%s: Calling _method_get", module)
        self._method_get("{0}/config/networkdevice".format(self.url_base))

    def get_device(self, device):
        """
        Get device detailed info
        :param device: User ID
        :return: result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        result = {"success": False, "response": "", "error": ""}

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        logger.info("%s: Calling ise.get with device: %s", module, device)
        resp = self.ise.get("{0}/config/networkdevice?filter=name.EQ.{1}".format(self.url_base, device))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        found_device = resp.json()

        if found_device["SearchResult"]["total"] == 1:
            logger.info(
                "%s: Calling ise.get with device id: %s",
                module,
                found_device["SearchResult"]["resources"][0]["id"],
            )
            resp = self.ise.get(
                "{0}/config/networkdevice/{1}".format(self.url_base, found_device["SearchResult"]["resources"][0]["id"])
            )
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
            if resp.status_code == 200:
                result["success"] = True
                result["response"] = resp.json()["NetworkDevice"]
                return result

            if resp.status_code == 404:
                result["response"] = "{0} not found".format(device)
                result["error"] = resp.status_code
                return result

            return ERS._pass_ersresponse(result, resp)

        if found_device["SearchResult"]["total"] == 0:
            result["response"] = "{0} not found".format(device)
            result["error"] = 404
            return result

        return ERS._pass_ersresponse(result, resp)

    def add_device(
        self,
        name,
        ip_address,
        radius_key,
        snmp_ro,
        dev_group,
        dev_location,
        dev_type,
        description="",
        snmp_v="TWO_C",
        dev_profile="Cisco",
    ):  # pylint: disable=too-many-arguments
        """
        Add a device
        :param snmp_v: Version of SNMP, default 2c
        :param name: name of device
        :param ip_address: IP address of device
        :param radius_key: Radius shared secret
        :param snmp_ro: SNMP read only community string
        :param dev_group: Device group name
        :param dev_location: Device location
        :param dev_type: Device type
        :param description: Device description
        :param dev_profile: Device profile
        :return: Result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        result = {"success": False, "response": "", "error": ""}

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        data = {
            "NetworkDevice": {
                "name": name,
                "description": description,
                "authenticationSettings": {
                    "networkProtocol": "RADIUS",
                    "radiusSharedSecret": radius_key,
                    "enableKeyWrap": "false",
                },
                "snmpsettings": {
                    "version": snmp_v,
                    "roCommunity": snmp_ro,
                    "pollingInterval": 3600,
                    "linkTrapQuery": "true",
                    "macTrapQuery": "true",
                    "originatingPolicyServicesNode": "Auto",
                },
                "profileName": dev_profile,
                "coaPort": 1700,
                "NetworkDeviceIPList": [{"ipaddress": ip_address, "mask": 32}],
                "NetworkDeviceGroupList": [dev_group, dev_type, dev_location, "IPSEC#Is IPSEC Device#No"],
            }
        }

        logger.info("%s: Calling ise.post with data: %s", module, data.json())
        resp = self.ise.post(
            "{0}/config/networkdevice".format(self.url_base),
            data=json.dumps(data),
            timeout=self.timeout,
        )
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())

        if resp.status_code == 201:
            result["success"] = True
            result["response"] = "{0} Added Successfully".format(name)
            return result

        return ERS._pass_ersresponse(result, resp)

    def delete_device(self, device):
        """
        Delete a device
        :param device: Device ID
        :return: Result dictionary
        """
        module = self.__class__.__name__ + "." + inspect.currentframe().f_code.co_name
        result = {"success": False, "response": "", "error": ""}

        self.ise.headers.update({"ACCEPT": "application/json", "Content-Type": "application/json"})

        logger.info("%s: Calling ise.get with device: %s", module, device)
        resp = self.ise.get("{0}/config/networkdevice?filter=name.EQ.{1}".format(self.url_base, device))
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())
        found_device = resp.json()
        if found_device["SearchResult"]["total"] == 1:
            device_oid = found_device["SearchResult"]["resources"][0]["id"]
            logger.info("%s: Calling ise.delete with device id: %s", module, device_oid)
            resp = self.ise.delete(
                "{0}/config/networkdevice/{1}".format(self.url_base, device_oid),
                timeout=self.timeout,
            )
            logger.info("%s: Raw response returned from ISE: %s", module, resp.json())

            if resp.status_code == 204:
                result["success"] = True
                result["response"] = "{0} Deleted Successfully".format(device)
                return result

            if resp.status_code == 404:
                result["response"] = "{0} not found".format(device)
                result["error"] = resp.status_code
                return result

            return ERS._pass_ersresponse(result, resp)

        if found_device["SearchResult"]["total"] == 0:
            result["response"] = "{0} not found".format(device)
            result["error"] = 404
            return result

        return ERS._pass_ersresponse(result, resp)
