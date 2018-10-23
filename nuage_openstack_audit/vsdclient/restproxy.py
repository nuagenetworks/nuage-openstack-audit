# Copyright 2016 NOKIA
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
import json
import logging
import time

import requests

# Suppress urllib3 warnings
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except AttributeError:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG = logging.getLogger(__name__)

REST_SUCCESS_CODES = range(200, 207)
REST_UNAUTHORIZED = 401
REST_NOT_FOUND = 404
REST_CONFLICT = 409
REST_CONFLICT_ERR_CODE = REST_CONFLICT
REST_SERV_UNAVAILABLE_CODE = 503

REST_EXISTS_INTERNAL_ERR_CODE = '2510'
REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE = '2039'
REST_VM_UUID_IN_USE_ERR_CODE = '2748'
REST_VLAN_EXISTS_ERR_CODE = '3316'
REST_VLAN_IN_USE_ERR_CODE = '7053'
REST_IFACE_EXISTS_ERR_CODE = '7006'
REST_ENT_PERMS_EXISTS_ERR_CODE = '4504'
REST_PG_EXISTS_ERR_CODE = '9501'
REST_DUPLICATE_ACL_PRIORITY = '2640'

VSD_RESP_OBJ = 3


class RESTProxyBaseException(Exception):
    message = 'An unknown exception occurred.'

    def __init__(self, **kwargs):
        try:
            super(RESTProxyBaseException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            super(RESTProxyBaseException, self).__init__(self.message)

    def __unicode__(self):
        return str(self.msg)


class RESTProxyError(RESTProxyBaseException):
    def __init__(self, message, error_code=None, vsd_code=None):
        self.code = 0
        if error_code:
            self.code = error_code
        self.vsd_code = vsd_code

        if self.code in (REST_CONFLICT_ERR_CODE, REST_SERV_UNAVAILABLE_CODE):
            self.message = message
        else:
            self.message = 'Error in REST call to VSD: %s' % message
        super(RESTProxyError, self).__init__()


class ResourceExistsException(RESTProxyError):
    def __init__(self, message):
        super(ResourceExistsException, self).__init__(
            message, REST_CONFLICT_ERR_CODE,
            vsd_code=REST_EXISTS_INTERNAL_ERR_CODE)


class ResourceNotFoundException(RESTProxyError):
    def __init__(self, message):
        super(ResourceNotFoundException, self).__init__(
            message, REST_NOT_FOUND)


class NuageServiceUnavailableException(RESTProxyError):
    def __init__(self, message):
        super(NuageServiceUnavailableException, self).__init__(
            message, REST_SERV_UNAVAILABLE_CODE)


class SingleThreadedRESTProxyServer(object):

    def __init__(self, server, base_uri, serverssl, verify_cert, serverauth,
                 auth_resource, organization, servertimeout=30, max_retries=5):
        self.scheme = "https" if serverssl else "http"
        self.server = server
        self.base_uri = base_uri
        self.verify_cert = verify_cert
        self.serverauth = serverauth
        self.auth_resource = auth_resource
        self.organization = organization
        self.timeout = servertimeout
        self.max_retries = max_retries
        self._session = None
        self.nuage_auth = None

    @property
    def session(self):
        if not self._session:
            self._session = requests.Session()
        return self._session

    @staticmethod
    def raise_rest_error(msg, exc=None, log_as_error=True):
        if log_as_error:
            LOG.error('RESTProxy: %s', msg)
        else:
            LOG.debug('RESTProxy: %s', msg)
        if exc:
            raise exc
        else:
            raise Exception(msg)

    @staticmethod
    def raise_error_response(response):
        try:
            errors = json.loads(response[3])
            log_as_error = False
            if response[0] == REST_SERV_UNAVAILABLE_CODE:
                log_as_error = True
                msg = 'VSD temporarily unavailable, ' + str(errors['errors'])
            else:
                msg = str(
                    errors['errors'][0]['descriptions'][0]['description'])

            if response[0] == REST_NOT_FOUND:
                e = ResourceNotFoundException(msg)
            else:
                vsd_code = str(errors.get('internalErrorCode'))
                e = RESTProxyError(msg, error_code=response[0],
                                   vsd_code=vsd_code)
            SingleThreadedRESTProxyServer.raise_rest_error(
                msg, e, log_as_error)
        except (TypeError, ValueError):
            if response[3]:
                LOG.error('REST response from VSD: %s', response[3])
            msg = ("Cannot communicate with SDN controller. Please do not "
                   "perform any further operations and contact the "
                   "administrator.")
            SingleThreadedRESTProxyServer.raise_rest_error(
                msg, NuageServiceUnavailableException(msg))

    def _rest_call(self, action, resource, data, extra_headers=None,
                   auth_renewal=False):
        uri = self.base_uri + resource
        url = "{}://{}{}".format(self.scheme, self.server, uri)
        body = json.dumps(data)
        headers = {
            'Content-type': 'application/json',
            'X-Nuage-Organization': self.organization,
        }
        if self.nuage_auth:
            headers['Authorization'] = self.nuage_auth
        if extra_headers:
            headers.update(extra_headers)

        if "X-Nuage-Filter" in headers:
            hdr = '[' + headers['X-Nuage-Filter'] + ']'
            LOG.debug('VSD_API REQ %s %s %s %s', action, uri, hdr, body)
        else:
            LOG.debug('VSD_API REQ %s %s %s', action, uri, body)

        ret = None
        for attempt in range(self.max_retries):
            try:
                response = self._create_request(action, url, body, headers)
                resp_data = response.text

                LOG.debug('VSD_API RSP %s %s %s', response.status_code,
                          response.reason, response.text)
                if response.status_code in REST_SUCCESS_CODES:
                    try:
                        resp_data = json.loads(response.text)
                    except ValueError:
                        # response was not JSON, ignore the exception
                        pass
                ret = (response.status_code, response.reason, response.text,
                       resp_data, response.headers, headers['Authorization'])
            except requests.exceptions.RequestException as e:
                LOG.error('ServerProxy: %(action)s failure, %(e)r', locals())
            else:
                if response.status_code != REST_SERV_UNAVAILABLE_CODE:
                    return ret
            time.sleep(1)
            LOG.debug("Attempt %s of %s", attempt + 1, self.max_retries)
        LOG.debug('After %d retries VSD did not respond properly.',
                  self.max_retries)
        return ret or 0, None, None, None, None, headers['Authorization']

    def _create_request(self, method, url, data, headers):
        """Create a HTTP(S) connection to the server and return the response.

        :param method: The HTTP method used for the request.
        :param url: The URL for the request.
        :param data: Any type of data to be sent along with the request.
        :param headers: Dictionary of HTTP headers.
        :return: :class:`requests.Response`
        """
        kwargs = {
            'data': data,
            'headers': headers,
            'timeout': self.timeout,
            'verify': self.verify_cert,
        }
        return self.session.request(method, url, **kwargs)

    def generate_nuage_auth(self):
        """Generate the Nuage authentication key."""
        encoded_auth = base64.encodestring(self.serverauth).strip()
        # use a temporary auth key instead of the expired auth key
        extra_headers = {'Authorization': 'Basic ' + encoded_auth}
        resp = self._rest_call('GET', self.auth_resource, '',
                               extra_headers=extra_headers,
                               auth_renewal=True)

        if not resp or resp[0] == 0:
            self.raise_rest_error("Could not establish a connection "
                                  "with the VSD. Please check VSD URI "
                                  "path in plugin config and verify "
                                  "IP connectivity.")
        elif resp[0] not in REST_SUCCESS_CODES \
                or not resp[3][0].get('APIKey'):
            self.raise_rest_error("Could not authenticate with the "
                                  "VSD. Please check the credentials "
                                  "in the plugin config")
        else:
            uname = self.serverauth.split(':')[0]
            new_uname_pass = uname + ':' + resp[3][0]['APIKey']
            encoded_auth = base64.encodestring(new_uname_pass).strip()
            self.nuage_auth = 'Basic ' + encoded_auth
            LOG.debug("[RESTProxy] New auth-token received %s",
                      self.nuage_auth)
            return resp

    def rest_call(self, action, resource, data, extra_headers=None):
        response = self._rest_call(
            action, resource, data, extra_headers=extra_headers)

        # If at all authentication expires with VSD, re-authenticate.
        if response[0] == REST_UNAUTHORIZED and response[1] == 'Unauthorized':
            # only renew the auth key if it hasn't been renewed yet
            if response[5] == self.nuage_auth:
                self.generate_nuage_auth()
                # When VSD license expires and if user will spin a VM
                # in this state then a proper error should be raised
                # eventually instead of going in to infinite loop.
                response = self._rest_call(
                    action, resource, data, extra_headers=extra_headers)
            else:
                response = self.rest_call(
                    action, resource, data, extra_headers=extra_headers)
        return response

    def get(self, resource, data='', extra_headers=None, required=False):
        response = self.rest_call('GET', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            headers = response[4]
            data = response[3]
            page_size = len(data)
            response_size = int(headers.get('X-Nuage-Count', 0))
            if response_size > page_size:
                # handle pagination
                num_pages = response_size // page_size + 1
                for page in range(1, num_pages):
                    headers = extra_headers or dict()
                    headers['X-Nuage-Page'] = str(page)
                    headers['X-Nuage-PageSize'] = str(page_size)
                    response = self.rest_call('GET', resource, data,
                                              extra_headers=headers)
                    if response[0] in REST_SUCCESS_CODES:
                        data.extend(response[3])
                    else:
                        self.raise_error_response(response)
            return data
        elif response[0] == REST_NOT_FOUND and not required:
            return ''
        else:
            self.raise_error_response(response)

    @staticmethod
    def retrieve_by_external_id(restproxy, resource, data):
        if not data.get('externalID'):
            return None
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "externalID IS '%s'" % data.get('externalID'),
        }
        return restproxy.get(resource, extra_headers=headers)

    @staticmethod
    def retrieve_by_name(restproxy, resource, data):
        if not data.get('name'):
            return None
        headers = {
            'X-NUAGE-FilterType': "predicate",
            'X-Nuage-Filter': "name IS '%s'" % data.get('name'),
        }
        return restproxy.get(resource, extra_headers=headers)

    def post(self, resource, data, extra_headers=None,
             on_res_exists=retrieve_by_external_id.__func__,
             ignore_err_codes=None):
        if ignore_err_codes is None:
            ignore_err_codes = [REST_EXISTS_INTERNAL_ERR_CODE]
        response = self.rest_call('POST', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_UNAUTHORIZED:
            # probably this is a POST of VM but user is not in CMS group
            self.raise_rest_error(
                'Unauthorized to this VSD API. '
                'Please check the user credentials in plugin config belong '
                'to CMS group in VSD.')
        elif response[0] == REST_CONFLICT_ERR_CODE:
            # Under heavy load, vsd responses may get lost. We must try find
            # the resource else it's stuck in VSD.
            errors = json.loads(response[3])
            if str(errors.get('internalErrorCode')) in ignore_err_codes:
                get_response = None
                if on_res_exists:
                    get_response = on_res_exists(self, resource, data)
                if not get_response:
                    errors = json.loads(response[3])
                    msg = str(errors['errors'][0]['descriptions'][0]
                              ['description'])
                    self.raise_rest_error(msg, ResourceExistsException(msg))
                return get_response
        self.raise_error_response(response)

    def put(self, resource, data, extra_headers=None):
        response = self.rest_call('PUT', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return
        else:
            errors = json.loads(response[3])
            vsd_code = str(errors.get('internalErrorCode'))
            if vsd_code == REST_NO_ATTR_CHANGES_TO_MODIFY_ERR_CODE:
                return
            self.raise_error_response(response)

    def delete(self, resource, data='', extra_headers=None, required=False):
        response = self.rest_call('DELETE', resource, data,
                                  extra_headers=extra_headers)
        if response[0] in REST_SUCCESS_CODES:
            return response[3]
        elif response[0] == REST_NOT_FOUND and not required:
            return None
        else:
            self.raise_error_response(response)
