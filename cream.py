"""
Class to configure Cisco ISE via the ERS API

Required:
requests
 - http://docs.python-requests.org/en/latest/
xmltodict
 - https://github.com/martinblech/xmltodict

Version: 0.1.4
"""
import json
import os
import re
import math

import requests
import xmltodict

base_dir = os.path.dirname(__file__)

import logging, inspect
logger = logging.getLogger(__name__)

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
        self.ise.verify = verify  # http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        self.disable_warnings = disable_warnings
        self.timeout = timeout
        self.pagesize = 100
        # self.retries = 3 - Future - for throttling
        self.ise.headers.update({'Connection': 'keep_alive'})

        if self.disable_warnings:
            requests.packages.urllib3.disable_warnings()

    @staticmethod
    def _to_json(content):
        """
        ISE API uses xml, this method will convert the xml to json.
        Why? JSON when you can, XML when you must!
        :param content: xml to convert to json
        :return: json result
        """
        return json.loads(
            json.dumps(
                xmltodict.parse(
                    content,
                    process_namespaces=True,
                    namespaces={
                        'ers.ise.cisco.com': None,
                        'identity.ers.ise.cisco.com': None,
                    }
                )
            )
        )

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

    def _method_get(self, url, item='', page=1):
        """
        Wrapper around the HTTP GET method to centrally handle error codes and paging.
        :param url: The URL to HTTP GET
        :param page: The page to retrieve
        :return: Dict result
        """
        module = self.__class__.__name__ + '.' + inspect.currentframe().f_code.co_name
        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        logger.info("%s: Retrieving page: %s, %s items per page", module, page, self.pagesize)
        resp = self.ise.get(url +'&size=' + str(self.pagesize) + '&page=' + str(page), timeout=self.timeout)
        json = ERS._to_json(resp.text)

        logger.info("%s: Status: %s", module, resp.status_code)
        if resp.status_code == 200:
            # Success
            result['success'] = True
            # Add the results we collected to the list.
            result['response'] = [(i['@name'], i['@id'], i['@description'])
                                  for i in json['searchResult']['resources']['resource']]

            logger.debug("%s: response: %s", module, result['response'])
            # Check for multiple pages.
            total = int(json['searchResult']['@total'])
            lastpage = math.ceil(total / self.pagesize)
            if (total > self.pagesize) and (page < lastpage):
                logger.debug("%s: We have more pages - This Page: %s, Total Pages: %s, Total Records: %s", module, page, lastpage, total)
                # Recurse to get the next page.
                innerresult = self._method_get(url=url, item=item, page=page+1)
                if innerresult['success']:
                    # Success, add the returned results to ours
                    for i in innerresult['response']:
                        result['response'].append([i[0], i[1], i[2]])
                else:
                    # error retrieving the next page, fail the whole tree.
                    result = innerresult
        elif resp.status_code == 404:
            # 404 Error from API
            result['response'] = '{0} not found'.format(item)
            result['error'] = resp.status_code
        else:
            # All other Errors
            result['response'] = json['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code

        return result

    def get_endpoint_groups(self):
        """
        Get all endpoint identity groups
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml'})

        url = '{0}/config/endpointgroup'.format(self.url_base)
        return self._method_get(url=url)

    def get_endpoint_group(self, group):
        """
        Get endpoint identity group details
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml'})

        url = '{0}/config/endpointgroup?filter=name.EQ.{1}'.format(self.url_base, group)
        return self._method_get(url=url, item=group)

    def add_endpoint_group(self, name='', description=''):
        """
        Add endpoint group
        :param name: Name of the endpoint group
        :param description: Description of the endpoint group
        :return: result dictionary
        """
        self.ise.headers.update(
            {'Content-Type': 'application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml; charset=utf-8'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        data = open(os.path.join(base_dir, 'xml/endpointgroup_add.xml'), 'r').read().format(
            'id', name, description
        )

        resp = self.ise.post('{0}/config/endpointgroup'.format(self.url_base), data=data, timeout=self.timeout)

        if resp.status_code == 201:
            result['success'] = True
            result['response'] = '{0} Added Successfully'.format(name)
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def update_endpoint_group(self, id, name='', description=''):
        """
        Update endpoint details
        :param id: ISE GUID of the endpoint group
        :param name: Name of the endpoint group
        :param description: Description of the endpoint group
        :return: result dictionary
        """
        self.ise.headers.update(
            {'Content-Type': 'application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml; charset=utf-8'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        data = open(os.path.join(base_dir, 'xml/endpointgroup_add.xml'), 'r').read().format(
            id, name, description
        )

        resp = self.ise.put('{0}/config/endpointgroup/{1}'.format(self.url_base, id), data=data, timeout=self.timeout)

        if resp.status_code == 200:
            result['success'] = True
            result['response'] = ERS._to_json(resp.text)['updatedFields']
            return result
        elif resp.status_code == 404:
            result['response'] = '{0} not found'.format(id)
            result['error'] = resp.status_code
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def delete_endpoint_group(self, id):
        """
        Delete endpoint
        :param id: ISE GUID of the endpoint group
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.delete('{0}/config/endpointgroup/{1}'.format(self.url_base, id),timeout=self.timeout)

        if resp.status_code == 204:
            result['success'] = True
            result['response'] = '{0} Deleted Successfully'.format(id)
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_endpoints(self, group=None):
        """
        Get all endpoints
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.endpoint.1.0+xml'})

        if (group == None):
            url = '{0}/config/endpoint'.format(self.url_base)
            return self._method_get(url=url)
        else:
            url = '{0}/config/endpoint?filter=groupId.EQ.{1}'.format(self.url_base, group)
            return self._method_get(url=url, item=group)

    def get_endpoint(self, mac_address):
        """
        Get endpoint details
        :param mac_address: MAC address of the endpoint
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac_address)

        if not is_valid:
            raise InvalidMacAddress('{0}. Must be in the form of AA:BB:CC:00:11:22'.format(mac_address))
        else:
            self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.endpoint.1.0+xml'})

            result = {
                'success': False,
                'response': '',
                'error': '',
            }

            resp = self.ise.get('{0}/config/endpoint?filter=mac.EQ.{1}'.format(self.url_base, mac_address),timeout=self.timeout)
            found_endpoint = ERS._to_json(resp.text)

            if found_endpoint['searchResult']['@total'] == '1':
                resp = self.ise.get('{0}/config/endpoint/{1}'.format(
                        self.url_base, found_endpoint['searchResult']['resources']['resource']['@id']))
                if resp.status_code == 200:
                    result['success'] = True
                    result['response'] = ERS._to_json(resp.text)['endpoint']
                    return result
                elif resp.status_code == 404:
                    result['response'] = '{0} not found'.format(mac_address)
                    result['error'] = resp.status_code
                    return result
                else:
                    result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                    result['error'] = resp.status_code
                    return result
            elif found_endpoint['searchResult']['@total'] == '0':
                result['response'] = '{0} not found'.format(mac_address)
                result['error'] = 404
                return result

            else:
                result['response'] = '{0} not found'.format(mac_address)
                result['error'] = resp.status_code
                return result

    def add_endpoint(self, mac_address, description='', group=None, profile=None):
        """
        Get endpoint details
        :param mac_address: MAC address of the endpoint
        :param description: Description of the endpoint
        :param group: Static Group ID (GUID) of the endpoint
        :param profile: Static profile (GUID) of the endpoint
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac_address)

        if not is_valid:
            raise InvalidMacAddress('{0}. Must be in the form of AA:BB:CC:00:11:22'.format(mac_address))
        else:
            self.ise.headers.update({'Content-Type': 'application/vnd.com.cisco.ise.identity.endpoint.1.0+xml; charset=utf-8'})

            result = {
                'success': False,
                'response': '',
                'error': '',
            }

            staticprofile = 'true'
            staticgroup = 'true'

            if profile is None:
                staticprofile = 'false'
                profile = ''
            if group is None:
                staticgroup = 'false'
                group = ''

            data = open(os.path.join(base_dir, 'xml/endpoint_add.xml'), 'r').read().format(
                'id', mac_address, group, description, 'None', 'None', 'False', profile, staticgroup, staticprofile
            )

            resp = self.ise.post('{0}/config/endpoint'.format(self.url_base), data=data, timeout=self.timeout)

            if resp.status_code == 201:
                result['success'] = True
                result['response'] = '{0} Added Successfully'.format(mac_address)
                return result
            else:
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result

    def update_endpoint(self, id, mac_address, description, group=None, profile=None):
        """
        Update endpoint details
        :param id: ISE GUID of the MAC address of the endpoint
        :param mac_address: MAC address of the endpoint
        :param description: Description of the endpoint
        :param group: Static Group ID (GUID) of the endpoint
        :param profile: Static profile (GUID) of the endpoint
        :return: result dictionary
        """
        is_valid = ERS._mac_test(mac_address)

        if not is_valid:
            raise InvalidMacAddress('{0}. Must be in the form of AA:BB:CC:00:11:22'.format(mac_address))
        else:
            self.ise.headers.update({'Content-Type': 'application/vnd.com.cisco.ise.identity.endpoint.1.0+xml; charset=utf-8'})

            result = {
                'success': False,
                'response': '',
                'error': '',
            }

            staticprofile = 'true'
            staticgroup = 'true'

            if profile is None:
                staticprofile = 'false'
                profile = ''
            if group is None:
                staticgroup = 'false'
                group = ''

            data = open(os.path.join(base_dir, 'xml/endpoint_add.xml'), 'r').read().format(
                id, mac_address, group, description, 'None', 'None', 'False', profile, staticgroup, staticprofile
            )

            resp = self.ise.put('{0}/config/endpoint/{1}'.format(self.url_base, id), data=data, timeout=self.timeout)

            if resp.status_code == 200:
                result['success'] = True
                result['response'] = ERS._to_json(resp.text)['updatedFields']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(mac_address)
                result['error'] = resp.status_code
                return result
            else:
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result

    def delete_endpoint(self, id):
        """
        Delete endpoint
        :param id: ISE GUID of the MAC address of the endpoint
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.endpoint.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.delete('{0}/config/endpoint/{1}'.format(self.url_base, id),timeout=self.timeout)

        if resp.status_code == 204:
            result['success'] = True
            result['response'] = '{0} Deleted Successfully'.format(id)
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_identity_groups(self):
        """
        Get all identity groups
        :return: result dictionary
        """
        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.identitygroup.1.0+xml'})

        resp = self.ise.get('{0}/config/identitygroup'.format(self.url_base),timeout=self.timeout)

        if resp.status_code == 200:
            result['success'] = True
            result['response'] = [(i['@name'], i['@id'], i['@description'])
                                  for i in ERS._to_json(resp.text)['searchResult']['resources']['resource']]
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_identity_group(self, group):
        """
        Get identity group details
        :param group: Name of the identity group
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.identitygroup.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get('{0}/config/identitygroup?filter=name.EQ.{1}'.format(self.url_base, group),timeout=self.timeout)
        found_group = ERS._to_json(resp.text)

        if found_group['searchResult']['@total'] == '1':
            resp = self.ise.get('{0}/config/identitygroup/{1}'.format(
                    self.url_base, found_group['searchResult']['resources']['resource']['@id']))
            if resp.status_code == 200:
                result['success'] = True
                result['response'] = ERS._to_json(resp.text)['identitygroup']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(group)
                result['error'] = resp.status_code
                return result
            else:
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result
        elif found_group['searchResult']['@total'] == '0':
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
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.internaluser.1.1+xml'})

        resp = self.ise.get('{0}/config/internaluser'.format(self.url_base),timeout=self.timeout)

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        json_res = ERS._to_json(resp.text)['searchResult']

        if resp.status_code == 200 and int(json_res['@total']) > 1:
            result['success'] = True
            result['response'] = [(i['@name'], i['@id'])
                                  for i in json_res['resources']['resource']]
            return result

        elif resp.status_code == 200 and int(json_res['@total']) == 1:
            result['success'] = True
            result['response'] = [(json_res['resources']['resource']['@name'],
                                   json_res['resources']['resource']['@id'])]
            return result

        elif resp.status_code == 200 and int(json_res['@total']) == 0:
            result['success'] = True
            result['response'] = []
            return result

        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_user(self, user_id):
        """
        Get user detailed info
        :param user_id: User ID
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.internaluser.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get('{0}/config/internaluser?filter=name.EQ.{1}'.format(self.url_base, user_id),timeout=self.timeout)
        found_user = ERS._to_json(resp.text)

        if found_user['searchResult']['@total'] == '1':
            resp = self.ise.get('{0}/config/internaluser/{1}'.format(
                    self.url_base, found_user['searchResult']['resources']['resource']['@id']),timeout=self.timeout)
            if resp.status_code == 200:
                result['success'] = True
                result['response'] = ERS._to_json(resp.text)['internaluser']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(user_id)
                result['error'] = resp.status_code
                return result
            else:
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result
        elif found_user['searchResult']['@total'] == '0':
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

        self.ise.headers.update({'Content-Type': 'application/vnd.com.cisco.ise.identity.internaluser.1.0+xml'})

        data = open(os.path.join(base_dir, 'xml/user_add.xml'), 'r').read().format(
                user_id, password, enable, first_name, last_name, email, description, user_group_oid)

        resp = self.ise.post('{0}/config/internaluser'.format(self.url_base), data=data, timeout=self.timeout)

        if resp.status_code == 201:
            result['success'] = True
            result['response'] = '{0} Added Successfully'.format(user_id)
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def delete_user(self, user_id):
        """
        Delete a user
        :param user_id: User ID
        :return: Result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.identity.internaluser.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get('{0}/config/internaluser?filter=name.EQ.{1}'.format(self.url_base, user_id),timeout=self.timeout)
        found_user = ERS._to_json(resp.text)

        if found_user['searchResult']['@total'] == '1':
            user_oid = found_user['searchResult']['resources']['resource']['@id']
            resp = self.ise.delete('{0}/config/internaluser/{1}'.format(self.url_base, user_oid), timeout=self.timeout)

            if resp.status_code == 204:
                result['success'] = True
                result['response'] = '{0} Deleted Successfully'.format(user_id)
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(user_id)
                result['error'] = resp.status_code
                return result
            else:
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result
        elif found_user['searchResult']['@total'] == '0':
            result['response'] = '{0} not found'.format(user_id)
            result['error'] = 404
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_device_groups(self):
        """
        Get a list tuples of device groups
        :return:
        """
        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.network.networkdevicegroup.1.0+xml'})

        resp = self.ise.get('{0}/config/networkdevicegroup'.format(self.url_base),timeout=self.timeout)

        if resp.status_code == 200:
            result['success'] = True
            result['response'] = [(i['@name'], i['@id'])
                                  for i in ERS._to_json(resp.text)['searchResult']['resources']['resource']]
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_device_group(self, device_group_oid):
        """
        Get a device group details
        :param device_group_oid: oid of the device group
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.network.networkdevicegroup.1.0+xml'})

        resp = self.ise.get('{0}/config/networkdevicegroup/{1}'.format(self.url_base, device_group_oid),timeout=self.timeout)

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        if resp.status_code == 200:
            result['success'] = True
            result['response'] = ERS._to_json(resp.text)['networkdevicegroup']
            return result
        elif resp.status_code == 404:
            result['response'] = '{0} not found'.format(device_group_oid)
            result['error'] = resp.status_code
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_devices(self):
        """
        Get a list of devices
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.network.networkdevice.1.0+xml'})

        resp = self.ise.get('{0}/config/networkdevice'.format(self.url_base),timeout=self.timeout)

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        json_res = ERS._to_json(resp.text)['searchResult']

        if resp.status_code == 200 and int(json_res['@total']) > 1:
            result['success'] = True
            result['response'] = [(i['@name'], i['@id'])
                                  for i in json_res['resources']['resource']]
            return result

        elif resp.status_code == 200 and int(json_res['@total']) == 1:
            result['success'] = True
            result['response'] = [(json_res['resources']['resource']['@name'],
                                   json_res['resources']['resource']['@id'])]
            return result

        elif resp.status_code == 200 and int(json_res['@total']) == 0:
            result['success'] = True
            result['response'] = []
            return result

        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def get_device(self, device):
        """
        Get device detailed info
        :param device: User ID
        :return: result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.network.networkdevice.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get('{0}/config/networkdevice?filter=name.EQ.{1}'.format(self.url_base, device),timeout=self.timeout)
        found_device = ERS._to_json(resp.text)

        if found_device['searchResult']['@total'] == '1':
            resp = self.ise.get('{0}/config/networkdevice/{1}'.format(
                    self.url_base, found_device['searchResult']['resources']['resource']['@id']),timeout=self.timeout)
            if resp.status_code == 200:
                result['success'] = True
                result['response'] = ERS._to_json(resp.text)['networkdevice']
                return result
            elif resp.status_code == 404:
                result['response'] = '{0} not found'.format(device)
                result['error'] = resp.status_code
                return result
            else:
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result
        elif found_device['searchResult']['@total'] == '0':
                result['response'] = '{0} not found'.format(device)
                result['error'] = 404
                return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def add_device(self,
                   name,
                   ip_address,
                   radius_key,
                   snmp_ro,
                   dev_group,
                   dev_location,
                   dev_type,
                   description='',
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

        self.ise.headers.update({'Content-Type': 'application/vnd.com.cisco.ise.network.networkdevice.1.0+xml'})

        data = open(os.path.join(base_dir, 'xml/device_add.xml'), 'r').read().format(
            name, ip_address, radius_key, snmp_ro, dev_group, dev_location, dev_type, description, dev_profile
        )

        resp = self.ise.post('{0}/config/networkdevice'.format(self.url_base), data=data, timeout=self.timeout)

        if resp.status_code == 201:
            result['success'] = True
            result['response'] = '{0} Added Successfully'.format(name)
            return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result

    def delete_device(self, device):
        """
        Delete a device
        :param device: Device ID
        :return: Result dictionary
        """
        self.ise.headers.update({'Accept': 'application/vnd.com.cisco.ise.network.networkdevice.1.0+xml'})

        result = {
            'success': False,
            'response': '',
            'error': '',
        }

        resp = self.ise.get('{0}/config/networkdevice?filter=name.EQ.{1}'.format(self.url_base, device))
        found_device = ERS._to_json(resp.text)

        if found_device['searchResult']['@total'] == '1':
            device_oid = found_device['searchResult']['resources']['resource']['@id']
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
                result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
                result['error'] = resp.status_code
                return result
        elif found_device['searchResult']['@total'] == '0':
                result['response'] = '{0} not found'.format(device)
                result['error'] = 404
                return result
        else:
            result['response'] = ERS._to_json(resp.text)['ersResponse']['messages']['message']['title']
            result['error'] = resp.status_code
            return result
