#
# Copyright (C) 2020 IBM. All Rights Reserved.
#
# See LICENSE file in the root directory
# of this source tree for licensing information.
#

import time
import requests
from os import path
from base64 import b64encode
from requests import Response


class SecuredAPI(object):
    '''
    An API client for APIs with security settings
    '''

    def __init__(self,
                 endpoint=None,
                 username=None, password=None,
                 token=None,
                 proxy=None,
                 debug=False):
        '''
        Create the SecuredAPI object to invoke APIs with security settings

        :param endpoint: in the form of (https://)host:port/path
        :param username: username, if using basic auth
        :param password: password, if using basic auth
        :param token: SEC token (authorized service), can be used instead of basic auth
        :param proxy: proxy if needed. Example: "proxy.us.company.com:8080"
        :param debug: print logs
        '''

        self.endpoint = endpoint
        self.proxy = {'https': proxy} if proxy else None
        self.debug = debug
        self.url = None  # latest URL used
        self.api_key = None  # encoded from username and password

        # Headers
        self.headers = {'Accept': 'application/json'}
        if username and password:
            credentials = '%s:%s' % (username, password)
            self.api_key = b64encode(credentials.encode()).decode()
            self.headers['authorization'] = 'Basic ' + self.api_key
        elif token:
            self.headers['authorization'] = token
        else:
            raise Exception("No credentials supplied")

    def _log(self, message):
        if self.debug:
            print(message)

    def _get_headers(self) -> dict:
        return self.headers.copy()

    def _get_url(self, service_path) -> str:
        if service_path:
            self.url = '/'.join(s.strip('/') for s in [self.endpoint, service_path])
        assert self.url, 'must provide service_path, or have recently provided a valid service_path'
        return self.url

    def _request(self, method='GET', service_path: str=None, params: dict={}, retry=0, retry_wait=2) -> Response:
        self._get_url(service_path)
        self._log('requests.%s: %s' % (method, self.url))
        if method == 'GET':
            resp = requests.get(self.url, params=params, headers=self._get_headers(), verify=False, proxies=self.proxy)
        elif method == 'POST':
            resp = requests.post(self.url, json=params, headers=self._get_headers(), verify=False, proxies=self.proxy)
        elif method == 'DELETE':
            resp = requests.delete(self.url, params=params, headers=self._get_headers(), verify=False, proxies=self.proxy)
        else:
            raise Exception('Unknown method: %s' % method)
        if resp.status_code >= 400:
            self._log('status_code: %s' % resp.status_code)
            if retry:
                time.sleep(retry_wait)
                return self._request(method, self.url, params, retry=retry - 1, retry_wait=retry_wait)
            else:
                print(resp.content)
                raise Exception("Could not %s: %s" % (method, self.url))
        return resp

    def get(self, service_path: str=None, params: dict={}, retry=0, retry_wait=2) -> Response:
        return self._request('GET', service_path, params, retry, retry_wait)

    def post(self, service_path: str=None, params: dict={}, retry=0, retry_wait=2) -> Response:
        return self._request('POST', service_path, params, retry, retry_wait)

    def delete(self, service_path: str=None, params: dict={}, retry=0, retry_wait=2) -> Response:
        return self._request('DELETE', service_path, params, retry, retry_wait)

    def get_endpoint(self, product: str) -> str:
        return self._get_url(product)
