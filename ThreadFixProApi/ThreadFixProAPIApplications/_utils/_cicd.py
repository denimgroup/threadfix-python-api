#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

import requests
import urllib3
import requests.exceptions
import requests.packages.urllib3

from ...API import API

class CICDAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro CI/CD API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/) NOTE: must include http:// TODO: make it so that it is required or implicitly added if forgotten
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        super().__init__(host, api_key, verify_ssl, timeout, user_agent, cert, debug)

    def create_cicd_pass_criteria(self, severity, max_allowed=None, max_introduced=None):
        """
        Creates a new CI/CD pass criteria
        :param severity: Name of severity
        :param max_allowed: The maximum number of vulnerabilities allowed for the Pass Criteria.  If no value is specified there is no limit.
        :param max_introduced: The maximum number of new vulnerabilities in a scan for the Pass Criteria.  If no value is specified there is no limit.
        """
        params = {'severity' : severity}
        if max_allowed:
            params['maxAllowed'] = max_allowed
        if max_introduced:
            params['maxIntroduced'] = max_introduced
        return super().request('POST', 'rest/cicd/passCriteria/create', params)

    def update_ci_cd_pass_criteria(self, cicd_id, severity, max_allowed=None, max_introduced=None):
        """
        Update CI/CD pass criteria
        :param cicd_id: CI/CD identifier
        :param severity: Name of severity
        :param max_allowed: The maximum number of vulnerabilities allowed for the Pass Criteria.  If no value is specified there is no limit.
        :param max_introduced: The maximum number of new vulnerabilities in a scan for the Pass Criteria.  If no value is specified there is no limit.
        """
        params = {'severity' : severity}
        if max_allowed:
            params['maxAllowed'] = max_allowed
        if max_introduced:
            params['maxIntroduced'] = max_introduced
        return super().request('POST', 'rest/cicd/passCriteria/' + str(cicd_id) + '/update', params)

    def list_cicd_pass_criteria(self):
        """
        Lists CI/CD pass criteria
        """
        return super().request('GET', 'rest/cicd/passCriteria')

    def get_cicd_pass_criteria_details(self, cicd_id):
        """
        Returns detailed information about the specified CI/CD pass criteria
        :param cicd_id: CI/CD identifier
        """
        return super().request('GET', 'rest/cicd/passCriteria/' + str(cicd_id) + '/detail')

    def delete_cicd_pass_criteria(self, cicd_id):
        """
        Deletes the specified CI/CD pass criteria
        :param cicd_id: CI/CD identifier
        """
        return super().request('DELETE', 'rest/cicd/passCriteria/' + str(cicd_id) + '/delete')

    def add_application_to_cicd_pass_criteria(self, pass_criteria_id, application_id):
        """
        Attaches the specified application to the specified pass criteria
        :param pass_criteria_id: Pass Criteria identifier
        :param application_id: Application identifier
        """
        return super().request('PUT', 'rest/cicd/passCriteria/' + str(pass_criteria_id) + '/addApplication/' + str(application_id))

    def remove_application_from_cicd_pass_criteria(self, pass_criteria_id, application_id):
        """
        Removes the specified application to the specified pass criteria
        :param pass_criteria_id: Pass Criteria identifier
        :param application_id: Application identifier
        """
        return super().request('DELETE', 'rest/cicd/passCriteria/' + str(pass_criteria_id) + '/removeApplication/' + str(application_id))

    def evaluate_cicd_pass_criteria(self, application_id, from_date=None, to_date=None):
        """
        Checks the specified application against all of the CI/CD pass criteria attached to it
        :param application_id: Application identifier
        :param from_date: Evaluate against any new open vulnerabilities from this date.  If no date is specified, the start date will be December 31, 1969.  
                        The time will be the start of day, 00:00:00. Format as yyyy-MM-dd
        :param to_date: Evaluate against any new open vulnerabilities until this date.  If no start date is specified, the end date will be the current date.  
                        The time will be the end of day, 23:59:59. Format as yyyy-MM-dd
        """
        params = {}
        if from_date:
            params['fromDate'] = from_date
        if to_date:
            parms['toDate'] = to_date
        return super().request('GET', 'rest/policy/status/application/' + str(application_id) + '/evaluate', params)

    def create_cicd_defect_reporter(self, severity, minimum=None, group_by=None):
        """
        Creates a new CI/CD defect reporter
        :param severity: Name of severity
        :param minimum: If true, includes all severities greater than the specified one as well.  Default value is false.  
        :param group_by: How to group vulnerabilities for defects
        """
        params = {'severity' : severity}
        if minimum:
            params['minimum'] = minimum
        if group_by:
            params['groupBy'] = group_by
        return super().request('POST', 'rest/cicd/defectReporting/create', params)

    def update_cicd_defect_reporter(self, cicd_id, severity, minimum=None, group_by=None):
        """
        Creates a new CI/CD defect reporter
        :param cicd_id: CI/CD identifier
        :param severity: Name of severity
        :param minimum: If true, includes all severities greater than the specified one as well.  Default value is false.  
        :param group_by: How to group vulnerabilities for defects
        """
        params = {'severity' : severity}
        if minimum:
            params['minimum'] = minimum
        if group_by:
            params['groupBy'] = group_by
        return super().request('PUT', 'rest/cicd/defectReporting/' + str(cicd_id) + '/update', params)

    def list_cicd_defect_reporters(self):
        """
        Lists CI/CD defect reporters
        """
        return super().request('GET', 'rest/cicd/defectReporting')

    def get_cicd_defect_reporter_details(self, cicd_id):
        """
        Returns CI/CD defect reporter details
        :param cicd_id: CI/CD identifier
        """
        return super().request('GET', 'rest/cicd/defectReporting/' + str(cicd_id) + '/detail')

    def delete_cicd_defect_reporter(self, cicd_id):
        """
        Deletes the CI/CD defect reporter
        :param cicd_id: CI/CD identifier
        """
        return super().request('DELETE', 'rest/cicd/defectReporting/' + str(cicd_id) + '/delete')

    def add_application_defect_tracker_to_cicd_defect_reporter(self, defect_reporter_id, app_defect_tracker_id):
        """
        Attaches the specified Application Defect Tracker to the specified CI/CD Defect Reporter
        :param defect_reporter_id: Defect Reporter identifier
        :param app_defect_tracker_id: App Defect Tracker identifier
        """
        return super().request('PUT', 'rest/cicd/defectReporting/' + str(defect_reporter_id) + '/addApplicationDefectTracker/' + str(app_defect_tracker_id))

    def remove_application_defect_tracker_to_cicd_defect_reporter(self, defect_reporter_id, app_defect_tracker_id):
        """
        Attaches the specified Application Defect Tracker to the specified CI/CD Defect Reporter
        :param defect_reporter_id: Defect Reporter identifier
        :param app_defect_tracker_id: App Defect Tracker identifier
        """
        return super().request('PUT', 'rest/cicd/defectReporting/' + str(defect_reporter_id) + '/removeApplicationDefectTracker/' + str(app_defect_tracker_id))