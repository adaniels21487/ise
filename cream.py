"""
Class to configure Cisco ISE via the ERS API
"""
import json
import os
import re
import math
from furl import furl

import requests

import logging, inspect
logger = logging.getLogger(__name__)

base_dir = os.path.dirname(__file__)


class InvalidMacAddress(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class ERS(object):
    def __init__(self, ise_node, ers_user, ers_pass, verify=False, disable_warnings=False, timeout=2):
        """
        Class to interact with Cisco ISE via the ERS API
        :param ise_node: IP Address of the primary admin ISE node
        :param ers_user: ERS username
        :param ers_pass: ERS password
        :param verify: Verify SSL cert
        :param disable_warnings: Disable requests warnings
        :param timeout: Query timeout
        """
        self.ise_node = ise_node
        self.user_name = ers_user
        self.user_pass = ers_pass

        self.url_base = 'https://{0}:9060/ers'.format(self.ise_node)
        self.ise = requests.session()
        self.ise.auth = (self.user_name, self.user_pass)
        # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.ise.verify = verify
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.ise.headers.update({'Connection': 'keep_alive'})

        if self.disable_warnings:
            requests.packages.urllib3.disable_warnings()

    @staticmethod
    def _mac_test(mac):
        """
        Test for valid mac address
        :param mac: MAC address in the form of AA:BB:CC:00:11:22
        :return: True/False
        """

        if re.search(r'([0-9A-F]{2}[:]){5}([0-9A-F]){2}', mac.upper()) is not None:
            return True
        else:
            return False

    @staticmethod
    def _pass_ersresponse(result, resp):
        result['response'] = resp.json()['ERSResponse']['messages'][0]['title']
        result['error'] = resp.status_code
        return result

    def _method_get(self, url, filter: str = None, size: int = 100, page: int = 1, all=True):
        """
        Generic GET method for accessing the ISE API
        :param url: Base URL for requesting lists
        :param filter: argument side of a ERS filter string. Default: None
        :param size: size of the page to return. Default: 100
        :param page: page to return. Default: 1
        :param all: do we want all results, not just this page. Default: True
        :return: result dictionary
        """
        result = {
            'success': False,
            'response': [],
            'error': '',
        }
        module = self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name
        logger.info("%s: Retrieving page: %s. %s items per page", module, page, size)

        # https://github.com/gruns/furl
        f = furl(url)
        f.args['page'] = page

        # Test for valid size 1<=x>=100
        if 1 <= size <= 100:
            f.args['size'] = size
        else:
            # Not in range, use the default 100
            f.args['size'] = 100

        # TODO add filter valication
        if filter:
            f.args['filter'] = filter

        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})
        resp = self.ise.get(f.url)
        logger.info("%s: Raw response returned from ISE: %s", module, resp.json())

        logger.info("%s: Status: %s", module, resp.status_code)
        if resp.status_code == 200:
            result['success'] = True
            # Append the results to the response list
            for i in resp.json()['SearchResult']['resources']]:
                if not i['description']:
                    i['description'] = ''
                result['response'].append = (i['name'], i['id'], i['description'])
            # Check for multiple pages.
            total = int(resp.json()['SearchResult']['total'])
            lastpage = math.ceil(total / size)
            if (total > size) and (page < lastpage):
                logger.debug("%s: We have more pages - This Page: %s, Total Pages: %s, Total Records: %s", module, page, lastpage, total)
                # Recurse to get the next page.
                innerresult = self._method_get(url=url, filter=filter, size=size, page=page+1, all=True)
                if innerresult['success']:
                    # Success, add the returned results to ours
                    for i in innerresult['response']:
                        result['response'].append([i[0], i[1], i[2]])
                else:
                    # error retrieving the next page, fail the whole tree.
                    result = innerresult
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_endpoint_groups(self):
        """
        Get all endpoint identity groups
        :return: result dictionary
        """
        return self._method_get('{0}/config/endpointgroup'.format(self.url_base))

    def get_endpoint_group(self, group):
        """
        Get endpoint identity group details
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }
        module = self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name

        resp = self.ise.get(
            '{0}/config/endpointgroup?filter=name.EQ.{1}'.format(self.url_base, group))
        found_group = resp.json()

        if found_group['SearchResult']['total'] == 1:
            resp = self.ise.get('{0}/config/endpointgroup/{1}'.format(
                self.url_base, found_group['SearchResult']['resources'][0]['id']))
            logger.debug("%s: EndpointGroup Results: %s", module, resp.json())

            if resp.status_code == 200:
                result['success'] = True
                result['response'] = resp.json()['EndPointGroup']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(group)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_group['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(group)
            result['error'] = 404
            return result

        else:
            return ERS._pass_ersresponse(result, resp)

    def update_endpoint_group(self, group_id, name='', description=''):
        """
        Update endpoint details
        :param id: ISE GUID of the endpoint group
        :param name: Name of the endpoint group
        :param description: Description of the endpoint group
        :return: result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        data = {"ERSEndPoint": {'id': group_id, 'name': name, 'description': description}}

        module = self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name
        logger.debug("%s: Data: %s", module, data)

        resp = self.ise.put('{0}/config/endpointgroup/{1}'.format(self.url_base, group_id),
                                data=json.dumps(data), timeout=self.timeout)
        if resp.status_code == 200:
            # TODO: Extract changed fields
            jsonresp = json.loads(resp.text)
            result['success'] = True
            result['response'] = jsonresp["UpdatedFieldsList"]
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_endpoints(self, group=None):
        """
        Get all endpoints
        :param group: Name of the identity group
        :return: result dictionary
        """
        if group is None:
            return self._method_get('{0}/config/endpoint'.format(self.url_base))
        else:
            return self._method_get('{0}/config/endpoint'.format(self.url_base), filter='groupId.EQ.{0}'.format(group))

    def get_endpoint(self, mac_address):
        """
        Get endpoint details
        :param mac_address: MAC address of the endpoint
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac_address)

        if not is_valid:
            raise InvalidMacAddress(
                '{0}. Must be in the form of AA:BB:CC:00:11:22'.format(mac_address))
        else:
            self.ise.headers.update(
                {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

            result = {
                'success': False,
                'response': '',
                'error': '',
            }

            resp = self.ise.get(
                '{0}/config/endpoint?filter=mac.EQ.{1}'.format(self.url_base, mac_address))
            found_endpoint = resp.json()

            if found_endpoint['SearchResult']['total'] == 1:
                resp = self.ise.get('{0}/config/endpoint/{1}'.format(
                    self.url_base, found_endpoint['SearchResult']['resources'][0]['id']))
                if resp.status_code == 200:
                    result['success'] = True
                    result['response'] = resp.json()['ERSEndPoint']
                    return result
                elif resp.status_code == 404:
                    result['response'] = '{0} not found'.format(mac_address)
                    result['error'] = resp.status_code
                    return result
                else:
                    return ERS._pass_ersresponse(result, resp)
            elif found_endpoint['SearchResult']['total'] == 0:
                result['response'] = '{0} not found'.format(mac_address)
                result['error'] = 404
                return result

            else:
                result['response'] = '{0} not found'.format(mac_address)
                result['error'] = resp.status_code
                return result

    def add_endpoint(self,
                     name,
                     mac,
                     group_id,
                     static_profile_assigment='false',
                     static_group_assignment='true',
                     profile_id='',
                     description=''):
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
        if not is_valid:
            raise InvalidMacAddress(
                '{0}. Must be in the form of AA:BB:CC:00:11:22'.format(mac))
        else:
            self.ise.headers.update(
                {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

            result = {
                'success': False,
                'response': '',
                'error': '',
            }

            data = {"ERSEndPoint": {'name': name, 'description': description, 'mac': mac,
                                    'profileId': profile_id, 'staticProfileAssignment': static_profile_assigment,
                                    'groupId': group_id, 'staticGroupAssignment': static_group_assignment,
                                    'customAttributes': {'customAttributes': {'key1': 'value1'}}}}

            resp = self.ise.post('{0}/config/endpoint'.format(self.url_base),
                                 data=json.dumps(data), timeout=self.timeout)
            if resp.status_code == 201:
                result['success'] = True
                result['response'] = '{0} Added Successfully'.format(name)
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def update_endpoint(self,
                        endpoint_id,
                        name,
                        mac,
                        group_id,
                        static_profile_assigment='false',
                        static_group_assignment='true',
                        profile_id='',
                        description=''):
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
        if not is_valid:
            raise InvalidMacAddress(
                '{0}. Must be in the form of AA:BB:CC:00:11:22'.format(mac))
        else:
            self.ise.headers.update(
                {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

            result = {
                'success': False,
                'response': '',
                'error': '',
            }

            data = {"ERSEndPoint": {'id': endpoint_id, 'name': name, 'description': description, 'mac': mac,
                                    'profileId': profile_id, 'staticProfileAssignment': static_profile_assigment,
                                    'groupId': group_id, 'staticGroupAssignment': static_group_assignment,
                                    'customAttributes': {'customAttributes': {'key1': 'value1'}}}}

            module = self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name
            logger.debug("%s: Data: %s", module, data)

            resp = self.ise.put('{0}/config/endpoint/{1}'.format(self.url_base, endpoint_id),
                                 data=json.dumps(data), timeout=self.timeout)
            if resp.status_code == 200:
                # TODO: Extract changed fields
                jsonresp = json.loads(resp.text)
                result['success'] = True
                result['response'] = jsonresp["UpdatedFieldsList"]
                return result
            else:
                return ERS._pass_ersresponse(result, resp)

    def delete_endpoint(self, mac):
        """
        Delete an endpoint
        :param mac: Endpoint Macaddress
        :return: Result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get(
            '{0}/config/endpoint?filter=mac.EQ.{1}'.format(self.url_base, mac))
        found_endpoint = resp.json()
        if found_endpoint['SearchResult']['total'] == 1:
            endpoint_oid = found_endpoint['SearchResult']['resources'][0]['id']
            resp = self.ise.delete(
                '{0}/config/endpoint/{1}'.format(self.url_base, endpoint_oid), timeout=self.timeout)

            if resp.status_code == 204:
                result['success'] = True
                result['response'] = '{0} Deleted Successfully'.format(mac)
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(mac)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_endpoint['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(mac)
            result['error'] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_identity_groups(self):
        """
        Get all identity groups
        :return: result dictionary
        """
        return self._method_get('{0}/config/identitygroup'.format(self.url_base))

    def get_identity_group(self, group):
        """
        Get identity group details
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get(
            '{0}/config/identitygroup?filter=name.EQ.{1}'.format(self.url_base, group))
        found_group = resp.json()

        if found_group['SearchResult']['total'] == 1:
            resp = self.ise.get('{0}/config/identitygroup/{1}'.format(
                self.url_base, found_group['SearchResult']['resources'][0]['id']))
            if resp.status_code == 200:
                result['success'] = True
                result['response'] = resp.json()['IdentityGroup']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(group)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_group['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(group)
            result['error'] = 404
            return result

        else:
            result['response'] = '{0} not found'.format(group)
            result['error'] = resp.status_code
            return result

    def get_users(self):
        """
        Get all internal users
        :return: List of tuples of user details
        """
        return self._method_get('{0}/config/internaluser'.format(self.url_base))

    def get_user(self, user_id):
        """
        Get user detailed info
        :param user_id: User ID
        :return: result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get(
            '{0}/config/internaluser?filter=name.EQ.{1}'.format(self.url_base, user_id))
        found_user = resp.json()

        if found_user['SearchResult']['total'] == 1:
            resp = self.ise.get('{0}/config/internaluser/{1}'.format(
                self.url_base, found_user['SearchResult']['resources'][0]['id']))
            if resp.status_code == 200:
                result['success'] = True
                result['response'] = resp.json()['InternalUser']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(user_id)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_user['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(user_id)
            result['error'] = 404
            return result
        else:
            result['response'] = 'Unknown error'
            result['error'] = resp.status_code
            return result

    def add_user(self,
                 user_id,
                 password,
                 user_group_oid,
                 enable='',
                 first_name='',
                 last_name='',
                 email='',
                 description=''):
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
        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        data = {"InternalUser": {'name': user_id, 'password': password, 'enablePassword': enable,
                                 'firstName': first_name, 'lastName': last_name, 'email': email,
                                 'description': description, 'identityGroups': user_group_oid}}

        resp = self.ise.post('{0}/config/internaluser'.format(self.url_base),
                             data=json.dumps(data), timeout=self.timeout)
        if resp.status_code == 201:
            result['success'] = True
            result['response'] = '{0} Added Successfully'.format(user_id)
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def delete_user(self, user_id):
        """
        Delete a user
        :param user_id: User ID
        :return: Result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get(
            '{0}/config/internaluser?filter=name.EQ.{1}'.format(self.url_base, user_id))
        found_user = resp.json()

        if found_user['SearchResult']['total'] == 1:
            user_oid = found_user['SearchResult']['resources'][0]['id']
            resp = self.ise.delete(
                '{0}/config/internaluser/{1}'.format(self.url_base, user_oid), timeout=self.timeout)

            if resp.status_code == 204:
                result['success'] = True
                result['response'] = '{0} Deleted Successfully'.format(user_id)
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(user_id)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_user['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(user_id)
            result['error'] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_device_groups(self):
        """
        Get a list tuples of device groups
        :return:
        """
        return self._method_get('{0}/config/networkdevicegroup'.format(self.url_base))

    def get_device_group(self, device_group_oid):
        """
        Get a device group details
        :param device_group_oid: oid of the device group
        :return: result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        resp = self.ise.get(
            '{0}/config/networkdevicegroup/{1}'.format(self.url_base, device_group_oid))

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        if resp.status_code == 200:
            result['success'] = True
            result['response'] = resp.json()['NetworkDeviceGroup']
            return result
        elif resp.status_code == 404:
            result['response'] = '{0} not found'.format(device_group_oid)
            result['error'] = resp.status_code
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def get_devices(self):
        """
        Get a list of devices
        :return: result dictionary
        """
        self._method_get('{0}/config/networkdevice'.format(self.url_base))

    def get_device(self, device):
        """
        Get device detailed info
        :param device: User ID
        :return: result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get(
            '{0}/config/networkdevice?filter=name.EQ.{1}'.format(self.url_base, device))
        found_device = resp.json()

        if found_device['SearchResult']['total'] == 1:
            resp = self.ise.get('{0}/config/networkdevice/{1}'.format(
                self.url_base, found_device['SearchResult']['resources'][0]['id']))
            if resp.status_code == 200:
                result['success'] = True
                result['response'] = resp.json()['NetworkDevice']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(device)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_device['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(device)
            result['error'] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def add_device(self,
                   name,
                   ip_address,
                   radius_key,
                   snmp_ro,
                   dev_group,
                   dev_location,
                   dev_type,
                   description='',
                   snmp_v='TWO_C',
                   dev_profile='Cisco'):
        """
        Add a device
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
        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        data = {'NetworkDevice': {'name': name,
                                  'description': description,
                                  'authenticationSettings': {
                                      'networkProtocol': 'RADIUS',
                                      'radiusSharedSecret': radius_key,
                                      'enableKeyWrap': 'false',
                                  },
                                  'snmpsettings': {
                                      'version': 'TWO_C',
                                      'roCommunity': snmp_ro,
                                      'pollingInterval': 3600,
                                      'linkTrapQuery': 'true',
                                      'macTrapQuery': 'true',
                                      'originatingPolicyServicesNode': 'Auto'
                                  },
                                  'profileName': dev_profile,
                                  'coaPort': 1700,
                                  'NetworkDeviceIPList': [{
                                      'ipaddress': ip_address,
                                      'mask': 32
                                  }],
                                  'NetworkDeviceGroupList': [dev_group, dev_type, dev_location, 'IPSEC#Is IPSEC Device#No']
                                  }
                }

        resp = self.ise.post('{0}/config/networkdevice'.format(self.url_base),
                             data=json.dumps(data), timeout=self.timeout)

        if resp.status_code == 201:
            result['success'] = True
            result['response'] = '{0} Added Successfully'.format(name)
            return result
        else:
            return ERS._pass_ersresponse(result, resp)

    def delete_device(self, device):
        """
        Delete a device
        :param device: Device ID
        :return: Result dictionary
        """
        self.ise.headers.update(
            {'ACCEPT': 'application/json', 'Content-Type': 'application/json'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get(
            '{0}/config/networkdevice?filter=name.EQ.{1}'.format(self.url_base, device))
        found_device = resp.json()
        if found_device['SearchResult']['total'] == 1:
            device_oid = found_device['SearchResult']['resources'][0]['id']
            resp = self.ise.delete(
                '{0}/config/networkdevice/{1}'.format(self.url_base, device_oid), timeout=self.timeout)

            if resp.status_code == 204:
                result['success'] = True
                result['response'] = '{0} Deleted Successfully'.format(device)
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(device)
                result['error'] = resp.status_code
                return result
            else:
                return ERS._pass_ersresponse(result, resp)
        elif found_device['SearchResult']['total'] == 0:
            result['response'] = '{0} not found'.format(device)
            result['error'] = 404
            return result
        else:
            return ERS._pass_ersresponse(result, resp)
