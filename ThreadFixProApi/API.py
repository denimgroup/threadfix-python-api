#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

import requests
import urllib3

from .ThreadFixProResponse import ThreadFixProResponse

class API(object):
    """Parent class to all APIs in the library. Use this if you have to make a request not already handled by the wrapper."""

    def __init__(self, host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/) NOTE: must include http://
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        self.api_version = '2.8.3' # Modify this when updating api
        self.host = host
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if not user_agent:
            self.user_agent = 'threadfix_pro_api/' + self.api_version 
        else:
            self.user_agent = user_agent

        self.cert = cert
        self.debug = debug  # Prints request and response information.

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disabling SSL warning messages if verification is disabled.

        if not str(self.host).startswith('http'): # If they didn't put http or https at the start it will fail the call
            self.host = 'http://' + self.host # Add only http as safe bet
        if str(self.host).endswith('/'): # Ensure it doesn't end with with a slash
            self.host = self.host[:-1]

        # Setup setters so that they can be modified outside of body for network API.
        if not headers:
            self.headers = {
                'Accept': 'application/json',
                'Authorization': 'APIKEY ' + self.api_key
            }
        else:
            self.headers = headers
       
    def add_versioning(self):
        # Combine host with start of all versioned calls (application only atm) to make sure they are called in the most recent version
        self.host = self.host + '/rest/v' + self.api_version

    def request(self, method, url, params=None, files=None):
        """Common handler for all HTTP requests."""
        if not params:
            params = {}

        

        try:
            if self.debug:
                print(method + ' ' + self.host + url)
                print(params)

            response = requests.request(method=method, url=self.host + url, params=params, files=files, headers=self.headers,
                                        timeout=self.timeout, verify=self.verify_ssl, cert=self.cert)

            if self.debug:
                print(response.status_code)
                print(response.text)

            try:
                json_response = response.json()
                try:
                    message = json_response['message']
                except KeyError:
                    message = 'Could not decode message from response'
                try:
                    response_code = json_response['responseCode']
                except KeyError:
                    response_code= response.status_code
                success = True if response_code >= 200 and response_code < 210 else False
                try:
                    data = json_response['object']
                except KeyError:
                    data = json_response

                return ThreadFixProResponse(message=message, success=success, response_code=response_code, data=data)
            except ValueError:
                return ThreadFixProResponse(message='JSON response could not be decoded.', success=False)
        except requests.exceptions.SSLError:
            return ThreadFixProResponse(message='An SSL error occurred.', success=False)
        except requests.exceptions.ConnectionError:
            return ThreadFixProResponse(message='A connection error occurred.', success=False)
        except requests.exceptions.Timeout:
            return ThreadFixProResponse(message='The request timed out after ' + str(self.timeout) + ' seconds.',
                                     success=False)
        except requests.exceptions.RequestException:
            return ThreadFixProResponse(message='There was an error while handling the request.', success=False)