#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class DefectTrackersAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Defect Trackers API instance.
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

    def create_defect_tracker(self, defect_tracker_type_id, name, url, default_username=None, default_password=None, default_product_name=None):
        """
        Creates a new defect tracker
        :param defect_tracker_type_id: The type of tracker to configure
        :param name: Name to give the defect tracker
        :param url: The url for the tracker
        :param default_username: The default username that can be used when attaching the tracker to an application
        :param default_password: The default password to use with the default username
        :param default_product_name: A default project that can be used when attaching the tracker to an application
        """
        params = {'defectTrackerTypeId' : defect_tracker_type_id, 'name' : name, 'url' : url}
        if default_username:
            params['defaultUsername'] = default_username
        if default_password:
            params['defaultPassword'] = default_password
        if default_product_name:
            params['defaultProductName'] = default_product_name
        return super().request('POST', '/defectTrackers/new', params)

    def get_defect_tracker_list(self):
        """
        Gets the list of Defect Trackers
        """
        return super().request('GET', '/defectTrackers/list')

    def get_application_defect_trackers(self, application_id):
        """
        Gets list of the Defect Trackers for an application
        :param application_id: Application identifier
        """
        return super().request('GET', '/applications/' + str(application_id) + '/appTrackers/listApplicationDefectTrackers')

    def add_defect_tracker_to_application(self, application_id, defect_tracker_id, username, password, project_name, 
                                            use_default_credentials=False, use_default_project=False):
        """
        Adds an existing Defect Tracker identified by its id to an application
        :param application_id: Application identifier
        :param defect_tracker_id: Defect Tracker identifier
        :param username: Username to access the Defect Tracker
        :param password: Password for the username to access the Defect Tracker
        :param project_name: Name of project the Defect Tracker files defects to
        :param use_default_credentials: If the tracker has default credentials set this to true 
        :param use_default project: If the tracker has a default project set this to true 
        """
        params = {'defectTrackerId' : defect_tracker_id}
        if not use_default_credentials:
            params['username'] = username
            params['password'] = password
        if not use_default_project:
            params['projectName'] = project_name
        return super().request('POST', '/applications/' + str(application_id) + '/appTrackers/addDefectTracker', params)

    def get_defect_tracker_fields(self, application_id):
        """
        Retrieves the fields for the defect tracker attached to the app with the given appId
        :params application_id: Application identifier
        """
        return super().request('GET', '/defects/' + str(application_id) + '/defectTrackerFields')

    def submit_defect(self, application_id, vulnerability_ids, additional_scanner_info=None):
        """
        Submits a defect for a vulnerability in the app with the given appId
        :param application_id: Application identifier
        :param vulnerability_ids: Ids for the vulnerabilities to file a defect for
        :param additional_scanner_info: Denotes if the defect should include extra fields specified in defectDescription.vm.
        """
        params = {'vulnerabilityIds' : vulnerability_ids}
        if additional_scanner_info:
            params['AdditionalScannerInfo'] = additional_scanner_info
        return super().request('POST', '/defects/' + str(application_id) + '/defectSubmission', params)

    def get_defect_tracker_types(self):
        """
        Returns a list of the availble defect tracker types and their IDs
        """
        return super().request('GET', '/defectTrackers/types')

    def get_defect_tracker_projects(self, defect_tracker_id):
        """
        Get a list of projects for a defect tracker. Only works if it has a default username and password
        :param defect_tracker_id: Defect Tracker identifier
        """
        return super().request('GET', '/defectTrackers/' + str(defect_tracker_id) + '/projects')

    def get_defect_tracker_fields_for_specified_tracker(self, application_id, application_tracker_id):
        """
        Retrieves the fields for the defect tracker attached to the app with the given appId
        :params application_id: Application identifier
        :params application_tracker_id: Application Tracker identifier
        """
        return super().request('GET', '/applications/' + str(application_id) + '/appTrackers/' + str(application_tracker_id) + '/defectTrackerFields')

    def submit_defect_to_specified_tracker(self, application_id, application_tracker_id, vulnerability_ids, additional_scanner_info=None):
        """
        Submits a defect to the tracker with the given appTrackerId attached to the application with the given appId
        :params application_id: Application identifier
        :params application_tracker_id: Application Tracker identifier
        :param vulnerability_ids: Ids for the vulnerabilities to file a defect for
        :param additional_scanner_info: Denotes if the defect should include extra fields specified in defectDescription.vm.
        """
        params = {'vulnerabilityIds' : vulnerability_ids}
        if additional_scanner_info:
            params['AdditionalScannerInfo'] = additional_scanner_info
        return super().request('POST', '/applications/' + str(application_id) + '/appTrackers/' + str(application_tracker_id) + '/detectSubmission', params)

    def update_defect_tracker(self, defect_tracker_id, default_username, default_password, name=None, url=None):
        """
        Update fields of a Defect Tracker
        :param defect_tracker_id: Defect Tracker identifier
        :param default_username: The user that will have access to the Defect Tracker
        :param default_password: Password that goes along with default username
        :param name: The new name for the tracker
        :param url: The new URL for the tracker
        """
        params = {'defaultUsername' : default_username, 'defaultPassword' : default_password}
        if name:
            params['name'] = name
        if url:
            params['url'] = url
        return super().request('PUT', '/defectTrackers/' + str(defect_tracker_id) + '/update', params)

    def list_defect_tracker_projects(self, defect_tracker_type_id, url, username, password, api_key):
        """
        Gets a list of projects for a Defect Tracker
        :param defect_tracker_type_id: The type of the defect tracker
        :param url: The URL for the tracker
        :param username: The username used to request Defect Tracker projects
        :param password: The password for the username
        :param api_key: The API key used to request Defect Tracker projects
        """
        params = {'defectTrackerTypeId' : defect_tracker_type_id, 'url' : url, 'username' : username, 'password' : password, 'apiKey' : api_key}
        return super().request('POST', '/defectTrackers/projects', params)
    
    def delete_defect_trackers(self, defect_tracker_id):
        """
        Deletes a Defect Tracker
        :param defect_tracker_id: Defect Tracker identifier
        """
        return super().request('DELETE', '/defectTrackers/' + str(defect_tracker_id) + '/update')

    def delete_defect_trackers(self, defect_tracker_profile_id):
        """
        Deletes a Defect Tracker
        :param defect_tracker_profile_id: Defect Tracker profile identifier
        """
        return super().request('DELETE', '/defectTrackers/profiles/' + str(defect_tracker_profile_id) + '/delete')

    def defect_creation_health_check(self):
        """
        Checks that defect tracker information is valid. 
        Supports only JIRA and HP Quality Center.
        Requires that Defect Reporter has been set up for at least one application.
        """
        return super().request('GET', '//defectTrackers/autoDefectCreationHealthCheck')

    def add_vulnerability_to_existing_defect(self, application_id, tracker_id, vulnerability_ids, defect_id):
        """
        Allows user to add a vulnerability to a defect that has already been created
        :param application_id: Application identifier
        :param tracker_id: Tracker identifier
        :param vulnerability_Ids: Ids for the vulnerabilities for which to file a defect.  All of the vulnerabilities are attached to the existing defect.
        :param defect_id: The defect ID from the defect tracker application
        """
        params = {'vulnerabilityIds' : vulnerability_ids, 'defectId' : defect_id}
        return super().request('POST', '/applications/' + str(application_id) + '/appTrackers/' + str(tracker_id) + '/attachToDefect', params)

    def delete_application_defect_trackers(self, application_id, tracker_id):
        """
        Deletes defect tracker for a specific application
        :param application_id: Application identifier
        :param tracker_id: Tracker identifier
        """
        return super().request('DELETE', '/applications/' + str(application_id) + '/appTrackers/' + str(tracker_id) + '/delete')

    def list_defect_tracker_profiles(self, tracker_id):
        """
        Gets all the Defect Profiles attached to the Defect Tracker
        :param tracker_id: Tracker identifier
        """
        return super().request('GET', '/defectTrackers/' + str(tracker_id) + '/profiles')