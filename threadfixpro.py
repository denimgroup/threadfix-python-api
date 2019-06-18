#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (brandon.spruth2@target.com), Jim Nelson (jim.nelson2@target.com),"
__copyright__ = "(C) 2018 Target Brands, Inc."
__contributors__ = ["Brandon Spruth", "Jim Nelson"]
__status__ = "Production"
__license__ = "MIT"

import json
import requests
import urllib3
import requests.exceptions
import requests.packages.urllib3

from . import __version__ as version


class ThreadFixProAPI(object):
    """An API wrapper to facilitate interactions to and from ThreadFix."""

    def __init__(self, host, api_key, verify_ssl=True, timeout=30, user_agent=None, cert=None, debug=False):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/)
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """

        self.host = host
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        if not user_agent:
            self.user_agent = 'threadfix_pro_api/' + version
        else:
            self.user_agent = user_agent

        self.cert = cert
        self.debug = debug  # Prints request and response information.

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disabling SSL warning messages if verification is disabled.

    # Team

    def create_team(self, name):
        """
        Creates a new team
        :param name: The name of the new team being created
        """
        params = {"name": name}
        return self._request('POST', 'rest/teams/new', params)

    def list_teams(self):
        """Retrieves all the teams."""
        return self._request('GET', 'rest/latest/teams')

    def get_team_by_id(self, team_id):
        """Retrieves team with id of team_id"""
        return self._request('GET', 'rest/latest/teams/{}'.format(team_id))

    # Application

    def create_application(self, team_id, name, url=None):
        """
        Creates an application under a given team.
        :param team_id: Team identifier.
        :param name: The name of the new application being created.
        :param url: The url of where the application is located.
        """
        params = {'name': name}
        if url:
            params['url'] = url
        return self._request('POST', 'rest/latest/teams/' + str(team_id) + '/applications/new', params)

    def get_application(self, application_id):
        """
        Retrieves an application using the given application id.
        :param application_id: Application identifier.
        """
        return self._request('GET', 'rest/latest/applications/' + str(application_id))

    def get_application_by_name(self, team_name, application_name):
        """
        Retrieves an application using the given team name and application name.
        :param team_name: The name of the team of the application to be retrieved.
        :param application_name: The name of the application to be retrieved.
        """
        return self._request('GET',
                             'rest/latest/applications/' + str(team_name) + '/lookup?name=' + str(application_name))

    def get_applications_by_team(self, team_id):
        """
        Retrieves all application using the given team id.
        :param team_id: Team identifier.
        """
        team_data = self.get_team_by_id(team_id)
        if team_data.success:
            new_data = []
            for app in team_data.data['applications']:
                new_data.append(app)
            return ThreadFixProResponse(message=team_data.message, success=team_data.success,
                                     response_code=team_data.response_code, data=new_data)
        else:
            return team_data

    # Scans

    def upload_scan(self, application_id, file_path):
        """
        Uploads and processes a scan file.
        :param application_id: Application identifier.
        :param file_path: Path to the scan file to be uploaded.
        """
        return self._request(
            'POST', 'rest/latest/applications/' + str(application_id) + '/upload',
            files={'file': open(file_path, 'rb')}
        )

    def list_scans(self, application_id):
        """
        List all scans for a given application
        :param application_id: Application identifier.
        """
        return self._request('GET', 'rest/latest/applications/' + str(application_id) + '/scans')

    def get_scan_details(self, scan_id):
        """
        List all scans for a given application
        :param scan_id: Scan identifier.
        """
        return self._request('GET', 'rest/latest/scans/' + str(scan_id))

    def download_scan(self, scan_id, filename):
        return self._request('GET', 'rest/latest/scans/' + str(scan_id) + '/download',
                             params={'scanFileName': filename})

    # Tasks

    def queue_scan(self, application_id, scanner_name, target_url = None, scan_config_id = None):
        """
        Queues up a scan with a given scanner for an application.
        Allows caller to optionally override a default application URL and to specify a specific scan configuration file.
        :param application_id Application identifier.
        :param scanner_name Name of the scanner to run
        :param target_url Alternate URL to scan versus the application's default URL
        :param scan_config_id Identifier of file stored in ThreadFix that contains the scanner configuration to use
        """
        params = {"applicationId": application_id, "scannerType": scanner_name}
        if target_url:
            params['targetURL'] = target_url
        if scan_config_id:
            params['scanConfigId'] = scan_config_id
        return self._request('POST', 'rest/latest/tasks/queueScan', params)

    # Utility

    def _request(self, method, url, params=None, files=None):
        """Common handler for all HTTP requests."""
        if not params:
            params = {}
        params['apiKey'] = self.api_key

        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json'
        }

        try:
            if self.debug:
                print(method + ' ' + url)
                print(params)

            response = requests.request(method=method, url=self.host + url, params=params, files=files, headers=headers,
                                        timeout=self.timeout, verify=self.verify_ssl, cert=self.cert)

            if self.debug:
                print(response.status_code)
                print(response.text)

            try:
                json_response = response.json()

                message = json_response['message']
                success = json_response['success']
                response_code = json_response['responseCode']
                data = json_response['object']

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


class ThreadFixProResponse(object):
    """Container for all ThreadFix API responses, even errors."""

    def __init__(self, message, success, response_code=-1, data=None):
        self.message = message
        self.success = success
        self.response_code = response_code
        self.data = data

    def __str__(self):
        if self.data:
            return str(self.data)
        else:
            return self.message

    def data_json(self, pretty=False):
        """Returns the data as a valid JSON string."""
        if pretty:
            return json.dumps(self.data, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self.data)
