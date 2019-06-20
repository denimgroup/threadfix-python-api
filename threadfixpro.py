#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Brandon Spruth (brandon.spruth2@target.com), Jim Nelson (jim.nelson2@target.com),"
__copyright__ = "(C) 2018 Target Brands, Inc."
__contributors__ = ["Brandon Spruth", "Jim Nelson", "Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

import json
import requests
import urllib3
import requests.exceptions
import requests.packages.urllib3

#from . import __version__ as version


class ThreadFixProAPI(object):
    """An API wrapper to facilitate interactions to and from ThreadFix."""

    def __init__(self, host, api_key, verify_ssl=True, timeout=30, user_agent=None, cert=None, debug=False):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/) NOTE: must include http:// TODO: make it so that it is required or implicitly added if forgotten
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
            self.user_agent = 'threadfix_pro_api/2.7.5' 
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

    def get_team_by_id(self, team_id):
        """
        Retrieves team with id of team_id'
        :param team_id: ID of the team being gotten
        """
        return self._request('GET', 'rest/teams/' + str(team_id))

    def get_team_by_name(self, team_name):
        """
        Retrieves team with name of team_name
        :param team_name: Name of the team being gotten
        """
        return self._request('GET', 'rest/teams/lookup?name=' + str(team_name))

    def get_all_teams(self):
        """
        Retrieves all the teams.
        """
        return self._request('GET', 'rest/teams')

    def update_team(self, team_id, name):
        """
        Updates team with teamId
        :param team_id: Team identifier
        :param name: New name to assign to the team
        """
        params = {'name' : name}
        return self._request('PUT', 'rest/teams/' + str(team_id) + '/update', params)

    def get_team_event_history(self, team_id, pages=None, page_size=None):
        """
        Lists event history for a team
        :param team_id: Team identifier
        :param pages: Number of events to return. By default this method will return up to 10 events
        :param page_size: Can be used to return a different page of events, with each page of events containing page_size events
        """
        params = {}
        if pages:
            params['page'] = pages
        if page_size:
            params['pageSize'] = page_size
        return self._request('POST', 'rest/events/organization/' + str(team_id), params)

    def delete_team(self, team_id):
        """
        Deletes a team by the provided teamId
        :param team_id: Team identifier
        """
        return self._request('DELETE', 'rest/teams/' + str(team_id) + '/delete')

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
        return self._request('POST', 'rest/teams/' + str(team_id) + '/applications/new', params)

    def get_application_by_id(self, application_id):
        """
        Retrieves an application using the given application id.
        :param application_id: Application identifier.
        """
        return self._request('GET', 'rest/applications/' + str(application_id))

    def get_application_by_name(self, team_name, application_name):
        """
        Retrieves an application using the given team name and application name.
        :param team_name: The name of the team of the application to be retrieved.
        :param application_name: The name of the application to be retrieved.
        """
        return self._request('GET',
                             'rest/applications/' + str(team_name) + '/lookup?name=' + str(application_name))

    def get_application_in_team_by_unique_id(self, team_name, unique_id):
        """
        Retrieves an application using the given team name and the applications unique id
        :param team_name: The name of the team of the application to be retrieved.
        :param unique_id: The unique id of the application to be retrieved.
        """
        return self._request('GET',
                             'rest/applications/' + str(team_name) + '/lookup?uniqueId=' + str(unique_id))

    def get_application_from_any_team_by_unique_id(self, unique_id):
        """
        Retrieves an application using the applications unique id ignoring team name
        :param unique_id: The unique id of the application to be retrieved.
        """
        return self._request('GET',
                             'rest/applications/allTeamLookup?uniqueId=' + str(unique_id))

    def update_application(self, application_id, name=None, url=None, unique_id=None, application_criticality=None, framework_type=None, repository_url=None, repository_type=None, repository_branch=None,
                         repository_user_name=None, repository_password=None, repository_folder=None, filter_set=None, team=None, skip_application_merge=None):
        """
        Updates the information of an application. Needs atleast one parameter to work
        :param application_id: Application identifier
        :param name: New name for application
        :param unique_id: New unique id for application
        :param application_criticality: New application criticality for application
        :param framework_type: New framework type for application
        :param repository_url: New repository for application
        :param repository_type: New type of repository, git or SVN, for application
        :param repository _branch: New branch of repository for application
        :param repository_user_name: New username for accessing the repository of the application
        :param repository_password: New password for accessing the repository of the application
        :param repository_folder: New folder for the repository
        :param filter_set: New filter set for application
        :param team: New team for application
        :param skip_application_merge: Whether or not to merge the application
        """
        params = {}
        if name:
            params['name'] = name
        if url:
            params['url'] = url
        if unique_id:
            params['uniqueId'] = unique_id
        if application_criticality:
            params['applicationCriticality'] = application_criticality
        if framework_type:
            params['frameworkType'] = framework_type
        if repository_url:
            params['repositoryUrl'] = repository_url
        if repository_type:
            params['repositoryType'] = repository_type
        if repository_branch:
            params['repositoryBranch'] = repository_branch
        if repository_user_name:
            params['repositoryUserName'] = repository_user_name
        if repository_password:
            params['repositoryPassword'] = repository_password
        if repository_folder:
            params['repositoryFolder'] = repository_folder
        if filter_set:
            params['filterSet'] = filter_set
        if team:
            params['team'] = team
        if skip_application_merge:
            params['skipApplicationMerge'] = skip_application_merge
        return self._request('PUT', 'rest/applications/' + str(application_id) + '/update', params)

    def set_application_parameters(self, framework_type, repository_url, application_id):
        """
        Sets application parameters
        :param framework_type: Sets the webframework the app is built on
        :param repository_url: The location of the repository where the app code can be found
        :param application_id: Application identifier
        """
        params = {'frameworkType' : framework_type, 'repositoryUrl' : repository_url}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/setParameters', params)

    def set_application_WAF(self, waf_id, application_id):
        """
        Sets the WAF id for the application
        :param waf_id: the WAF id for the application
        :param application_id: Application identifier
        """
        params = {'wafId' : waf_id}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/setWaf', params)

    def set_application_URL(self, url, application_id):
        """
        Sets the application URL
        :param url: The url for the application
        :param application_id: Application identifier
        """
        params = {'url' : url}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/addUrl', params)
    
    def add_manual_finding(self,  application_id, vuln_type, long_description, severity, is_static=False, native_id=None, parameter=None, file_path=None, column=None,
                            line_text=None, line_number=None, full_url=None, path=None):
        """
        Adds manual finding to application
        :param application_id: Application identifier
        :param vuln_type: Name of the vulnerability
        :param long_description: General description of the issue
        :param severity: Severity level of vulnerability from 1-5
        :param is_static: Is the finding from a static or dynamic test
        :param native_id: Identifier for the vulnerability
        :param parameter: Requested parameters for vulnerability
        :param file_path: (Static only) Location of source file
        :param column: (Static only) Column number for finding vulnerability source
        :param line_text: (Static only) Line text for finding vulnerability source
        :param line_number: (Static only) Line number for finding vulnerability source
        :param full_url: (Dynamic only) Absolute URL to page with vulnerability
        :param path: (Dynamic only) Relative path to the page with the vulnerability
        """
        params = {'vulnType' : vuln_type, 'long_description' : long_description, 'severity' : severity}
        if native_id:
            params['nativeId'] = native_id
        if parameter:
            params['parameter'] = parameter
        if file_path:
            params['filePath'] = file_path
        if column:
            params['column'] = column
        if line_text:
            params['lineText'] = line_text
        if line_number:
            params['lineNumber'] = line_number
        if full_url:
            params['fullUrl'] = full_url
        if path:
            params['path'] = path
        return self._request('POST', 'rest/applications/' + str(application_id) + 'addFinding', params)

    def create_application_version(self, version_name, version_date, application_id):
        """
        Creates an application version
        :param version_name: Name of the version of the application
        :param version_date: Date of the version of the application
        :param application_id: Application identifier
        """
        params = {'versionName' : version_name, 'versionDate' : version_date}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/version', params)

    def update_application_version(self, application_id, version_id, version_name=None, version_date=None):
        """
        Updates the version data for an application
        :param application_id: Application identifier
        :param version_id: Version identifier
        :param version_name: New name for version
        :param version_date: New date for version
        """
        params = {}
        if version_name:
            params['versionName'] = version_name
        if version_date:
            params['versionDate'] = version_date
        return self._request('PUT', 'rest/applications/' + str(application_id) + '/version/' + str(version_id))
    
    def delete_application_version(self, application_id, version_id):
        """
        Deletes the version data for an application
        :param application_id: Application identifier
        :param version_id: Version identifier
        """
        return self._request('DELETE', 'rest/applications/' + str(application_id) + '/version/' + str(version_id))

    def attach_file_to_application(self, application_id, file_path, file_name=None,):
        """
        Uploads and attaches a file. to an application
        :param application_id: Application identifier.
        :param file_path: Path to the file to be uploaded.
        :param file_name: A name to override the file name when uploaded
        """
        params={}
        if file_name:
            params['filename'] = file_name
        files={'file': open(file_path, 'rb')}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/attachFile', params, files)

    def delete_applications(self, application_id):
        """
        Deletes an application
        :param application_id: Application identifier
        """
        return self._request('DELETE', 'rest/applications/' + str(application_id) + '/delete')

    def create_application_metadata(self, key, title, description, application_id):
        """
        Creates metadata for an application
        :param key: The id of an active Application Metadata Key
        :param title: The name of an active Application Metadata Key
        :param description: The value for the Metadata
        :param application_id: Application identifier
        """
        params = {'key' : key, 'title' : title, 'description' : description}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/metadata/new', params)

    def edit_application_metada(self, description, application_id, app_metadata_id):
        """
        Edits an application's metadata
        :param description: New value for Metadata
        :param application_id: Application identifier
        :param app_metadata_id: Metadata identifier
        """
        params = {'description' : description}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/metadata/' + str(app_metadata_id) + '/update')

    def delete_application_metadata(self, application_id, app_metadata_id):
        """
        Deletes an application's metadata
        :param application_id: Application identifier
        :param app_metadata_id: Metadata identifier
        """
        return self._request('DELETE', 'rest/applications/' + str(application_id) + '/metadata/' + str(app_metadata_id) + '/delete')

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
    
    # Defect Trackers

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
        return self._request('POST', 'rest/defectTrackers/new', params)

    def get_defect_tracker_list(self):
        """
        Gets the list of Defect Trackers
        """
        return self._request('GET', 'rest/defectTrackers/list')

    def get_application_defect_trackers(self, application_id):
        """
        Gets list of the Defect Trackers for an application
        :param application_id: Application identifier
        """
        return self._request('GET', 'rest/applications/' + str(application_id) + '/appTrackers/listApplicationDefectTrackers')

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
        return self._request('POST', 'rest/applications/' + str(application_id) + '/appTrackers/addDefectTracker', params)

    def get_defect_tracker_fields(self, application_id):
        """
        Retrieves the fields for the defect tracker attached to the app with the given appId
        :params application_id: Application identifier
        """
        return self._request('GET', 'rest/defects/' + str(application_id) + '/defectTrackerFields')

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
        return self._request('POST', 'rest/defects/' + str(application_id) + '/defectSubmission', params)

    def get_defect_tracker_types(self):
        """
        Returns a list of the availble defect tracker types and their IDs
        """
        return self._request('GET', 'rest/defectTrackers/types')

    def get_defect_tracker_projects(self, defect_tracker_id):
        """
        Get a list of projects for a defect tracker. Only works if it has a default username and password
        :param defect_tracker_id: Defect Tracker identifier
        """
        return self._request('GET', 'rest/defectTrackers/' + str(defect_tracker_id) + '/projects')

    def get_defect_tracker_fields_for_specified_tracker(self, application_id, application_tracker_id):
        """
        Retrieves the fields for the defect tracker attached to the app with the given appId
        :params application_id: Application identifier
        :params application_tracker_id: Application Tracker identifier
        """
        return self._request('GET', 'rest/applications/' + str(application_id) + '/appTrackers/' + str(application_tracker_id) + '/defectTrackerFields')

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
        return self._request('POST', 'rest/applications/' + str(application_id) + '/appTrackers/' + str(application_tracker_id) + '/detectSubmission', params)

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
        return self._request('PUT', 'rest/defectTrackers/' + str(defect_tracker_id) + '/update', params)

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
        return self._request('POST', 'rest/defectTrackers/projects', params)
    
    def delete_defect_trackers(self, defect_tracker_id):
        """
        Deletes a Defect Tracker
        :param defect_tracker_id: Defect Tracker identifier
        """
        return self._request('DELETE', 'rest/defectTrackers/' + str(defect_tracker_id) + '/update')

    def delete_defect_trackers(self, defect_tracker_profile_id):
        """
        Deletes a Defect Tracker
        :param defect_tracker_profile_id: Defect Tracker profile identifier
        """
        return self._request('DELETE', 'rest/defectTrackers/profiles/' + str(defect_tracker_profile_id) + '/delete')

    def defect_creation_health_check(self):
        """
        Checks that defect tracker information is valid. 
        Supports only JIRA and HP Quality Center.
        Requires that Defect Reporter has been set up for at least one application.
        """
        return self._request('GET', '/rest/defectTrackers/autoDefectCreationHealthCheck')

    def add_vulnerability_to_existing_defect(self, application_id, tracker_id, vulnerability_ids, defect_id):
        """
        Allows user to add a vulnerability to a defect that has already been created
        :param application_id: Application identifier
        :param tracker_id: Tracker identifier
        :param vulnerability_Ids: Ids for the vulnerabilities for which to file a defect.  All of the vulnerabilities are attached to the existing defect.
        :param defect_id: The defect ID from the defect tracker application
        """
        params = {'vulnerabilityIds' : vulnerability_ids, 'defectId' : defect_id}
        return self._request('POST', 'rest/applications/' + str(application_id) + '/appTrackers/' + str(tracker_id) + '/attachToDefect', params)

    def delete_application_defect_trackers(self, application_id, tracker_id):
        """
        Deletes defect tracker for a specific application
        :param application_id: Application identifier
        :param tracker_id: Tracker identifier
        """
        return self._request('DELETE', 'rest/applications/' + str(application_id) + '/appTrackers/' + str(tracker_id) + '/delete')

    # Policies

    def get_policy(self, policy_id):
        """
        Get details for a policy
        :param policy_id: Policy identifier
        """
        return self._request('GET', 'rest/policies/' + str(policy_id))

    def get_all_policies(self):
        """
        Get a list of all policies in ThreadFix
        """
        return self._request('GET', 'rest/policies')

    def get_application_policy_status(self, application_id):
        """
        Get the status for all policies attached to the application with the provided appId
        :param application_id: Application identifier
        """
        return self._request('GET', 'rest/applications/' + str(application_id) + '/policyStatuses')

    def add_application_to_policy(self, policy_id, application_id):
        """
        Adds an application to a policy
        :param policy_id: Policy identifier
        :param application_id: Application identifier
        """
        return self._request('POST', 'rest/policies/' + str(policy_id) + '/application/' + str(application_id))

    def ad_hoc_policy_evaluation(self, application_id, policy_id):
        """
        Gets the status of a policy even if the policy is not attached to the application
        :param application_id: Application identifier
        :param policy_id: Policy identifier
        """
        return self._request('GET', 'rest/applications/' + str(application_id) + '/policy/eval?policyId=' + str(policy_id))

    def retrieve_all_policies(self, team_id):
        """
        Get details for all policies attached to a team
        :param team_id: Team identifier
        """
        return self._request('GET', 'rest/policies/team/' + str(team_id))

    def add_policy_to_team(self, policy_id, team_id):
        """
        Adds a policy to a team and any application associated with that team
        :param policy_id: Policy identifier
        :param team_id: Team identifier
        """
        return self._request('POST', 'rest/policies/' + str(policy_id) + '/team/' + str(team_id))

    def remove_policy_to_team(self, policy_id, team_id):
        """
        Removes a policy to a team and any application associated with that team
        :param policy_id: Policy identifier
        :param team_id: Team identifier
        """
        return self._request('DELETE', 'rest/policies/' + str(policy_id) + '/team/' + str(team_id) + '/remove')

    # Scans

    def get_scan_details(self, scan_id):
        """
        List all scans for a given application
        :param scan_id: Scan identifier.
        """
        return self._request('GET', 'rest/scans/' + str(scan_id))

    def list_scans(self, application_id):
        """
        List all scans for a given application
        :param application_id: Application identifier.
        """
        return self._request('GET', 'rest/applications/' + str(application_id) + '/scans')

    def upload_scan(self, application_id, file_path):
        """
        Uploads and processes a scan file.
        :param application_id: Application identifier.
        :param file_path: Path to the scan file to be uploaded.
        """
        return self._request(
            'POST', 'rest/applications/' + str(application_id) + '/upload',
            files={'file': open(file_path, 'rb')}
        )
    
    def multiple_file_scan_upload(self, application_id, file_paths, bulk_upload=False):
        """
        Uploads and processes multiple scan file.
        :param application_id: Application identifier.
        :param file_path: Path to the scan file to be uploaded.
        :param bulk_upload: Upload files as a single scan (False) or separate scans (True)
        """
        return self._request(
            'POST', 'rest/applications/' + str(application_id) + '/upload/multi',
            files= [{'file' : open(file_path, 'rb')} for file_path in file_paths]
        )

    def check_pending_scan_status(self, application_id, scan_id):
        """
        Check the status of a scan after it has been queued
        :param application_id: Application identifier
        :param scan_id: Scan identifier
        """
        return self._request('GET', 'rest/applications/' + str(application_id) + '/pendingScan/' + str(scan_id) + '/status')

    def download_scan(self, scan_id, filename):
        """
        Download a scan by id
        :param scan_id: Scan identifier
        :param filename: Download location
        """
        return self._request('GET', 'rest/scans/' + str(scan_id) + '/download',
                             params={'scanFileName': filename})

    def delete_scan(self, scan_id):
        """
        Queues the specified scan for deletion
        :param scan_id: Scan identifier
        """
        return self._request('DELETE', 'rest/scans/' + str(scan_id) + '/delete')

    def edit_scan_metadata(self, metadata_key_id, key=None, description=None, title=None):
        """
        Updates scan metadata
        :param metadata_key_id:
        :param key: The scan metadata key for the metadata which will be edited
        :param description: New text for description field
        :param title: Scan Metadata key title. Used if key param is not present
        """
        params = {}
        if key:
            params['key'] = key
        if description:
            params['description'] = description
        if title:
            params['title'] = title
        return self._request('POST', 'rest/customize/scanmetadata/keys/' + str(metadata_key_id) + '/update', params)

    def create_scan_metadata(self, scan_id, key, description, title=None):
        """
        Creates new scan metadata
        :param scan_id: Scan identifier
        :param key: The metadata key ID
        :param description: Text description of metadata
        :param title: The scan metadata key title.
        """
        params = {'key' : key, 'description' : description}
        if title:
            params['title'] = title
        return self._request('POST', 'rest/scans/' + str(scan_id) + '/metadata/new', params)

    def delete_scan_metadata(self, scan_id, scan_metadata_key_id):
        """
        Deletes scan metadata from scan
        :param scan_id: Scan identifier
        :param scan_metadata_key_id: Scan Metadata Key identifier
        """
        return self._request('POST', 'rest/scans/' + str(scan_id) + '/metadata/' + str(scan_metadata_key_id) + '/delete')

    # Tags

    def create_tag(self, name, tag_type="APPLICATION"):
        """
        Creats a new tag with the given name
        :param name: Name to assign the new tag. 60 character limit
        :param tag_type: The type of tag to create
        """
        params = {'name' : name, 'tagType' : tag_type}
        return self._request('POST', 'rest/tags/new', params)

    def get_tag_by_id(self, tag_id):
        """
        Gets tag by the given tagId
        :param tag_id: Tag identifier
        """
        return self._request('GET', 'rest/tags/' + str(tag_id))

    def get_tag_by_name(self, tag_name):
        """
        Gets tag by the given name
        :param tag_name: The name of a tag to be gotten
        """
        return self._request('GET', 'rest/tags/lookup?name=' + str(tag_name))

    def get_tags_by_vulnerability(self, vuln_id):
        """
        Gets tags attached to a given vulnerability
        :param vuln_id: The identifier of the vulnerability to get the tags from
        """
        return self._request('GET', 'rest/tags/vulnerabilities' + str(vuln_id))

    def get_all_tags(self):
        """
        Returns a list of all tags and returns their JSON
        """
        return self._request('GET', 'rest/tags/index')

    def list_tags(self):
        """
        Retrieves a list of only tag names, ids, and types.
        """
        return self._request('GET', 'rest/tags/list')

    def update_tag(self, tag_id, name):
        """
        Updates the name of the tag with the given tagId
        :param tag_id: Tag identifier
        :param name: New name to assign the tag
        """
        params = {'name' : name}
        return self._request('POST', 'rest/tags/' + str(tag_id) + '/update', params)

    def add_tag_to_application(self, application_id, tag_id):
        """
        Attaches the tag with the given tagId to the app with the given appId
        :param application_id: Application identifier
        :param tag_id: Tag identifier
        """
        return self._request('POST', 'rest/applications/' + str(application_id) + '/tags/add/' + str(tag_id))

    def remove_tag_to_application(self, application_id, tag_id):
        """
        Removes the tag with the given tagId to the app with the given appId
        :param application_id: Application identifier
        :param tag_id: Tag identifier
        """
        return self._request('POST', 'rest/applications/' + str(application_id) + '/tags/remove/' + str(tag_id))

    def delete_tag(self, tag_id):
        """
        Deletes the tag with the given tagId
        :params tag_id: Tag identifier
        """
        return self._request('POST', 'rest/tags/' + str(tag_id) + '/delete')

    def list_applications_for_tag(self, tag_id):
        """
        Returns the JSON of the apps that have the tag with the given tagId
        :params tag_id: Tag identifier
        """
        return self._request('GET', 'rest/tags/' + str(tag_id) + '/listApplications')

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
        return self._request('POST', 'rest/tasks/queueScan', params)

    def set_task_config(self, application_id, scanner_type, file_path):
        """
        Uploads a Scan Agent configuration file to an application that will be used by default for tasks with the relevant scanner.
        :param application_id: The id for the app to upload the file to
        :param scanner_type: The scanner the file will be used as a base for
        :param file: The file to upload
        """
        params = {'appId' : application_id, 'scannerType' : scanner_type}
        files = {'file' : open(file_path, 'rb')}
        return self._request('POST', 'rest/tasks/setTaskConfig', params, files)

    def request_scan_agent_key(self):
        """
        Request a Secure Scan Agent Key.  This key is used to request scan agent tasks and prevent multiple scan agents from interacting with the same task.
        """
        return self._request('GET', 'rest/tasks/requestScanAgentKey')

    def request_task(self, scanners, agent_config_path, scan_agent_secure_key):
        """
        Requests the next available task off the queue.
        :param scanners: Use this to only select taskss from specified scanner types
        :param agent_config_path: The path to the scangent.properties file your scan agent generated
        :param scan_agent_secure_key: A Secure Scan Agent Key obtained from the “Request Scan Agent Key” call
        """
        params = {'scanners' : scanners, 'scanAgentSecureKey' : scan_agent_secure_key}
        files = {'files' : open(agent_config_path, 'rb')}
        return self._request('POST', 'rest/tasks/requestTask', params, files)

    def update_task_status(self, scan_queue_task_id, message, scan_agent_secure_key, secure_task_key):
        """
        Sends a status update to ThreadFix for the Scan Agent
        :param scan_queue_task_id: ID for the Scan Agent Task to update
        :param message: The status update message
        :param scan_agent_secure_key: A Secure Scan Agent Key obtained from the “Request Scan Agent Key” call
        :param secure_task_key: The Secure Task Key that was returned when the Task was assigned from the queue
        """
        params = {'scanQueueTaskId' : scan_queue_task_id,  'message' : message, 'scanAgentSecureKey' : scan_agent_secure_key, 'secureTaskKey' : secure_task_key}
        return self._request('POST', 'rest/tasks/taskStatusUpdate', params)

    def complete_task(self, scan_queue_task_id, file_path, scan_agent_secure_key, secure_task_key):
        """
        Marks a task as completed and uploads the scan file to the task’s application
        :param scan_queue_task_id: ID for the Scan Agent Task
        :param file_path: The path to the file to upload
        :param scan_agent_secure_key: A Secure Scan Agent Key obtained from the “Request Scan Agent Key” call
        :param secure_task_key: The Secure Task Key that was returned when the Task was assigned from the queue
        """
        params = {'scanQueueTaskId' : scan_queue_task_id, 'scanAgentSecureKey' : scan_agent_secure_key, 'secureTaskKey' : secure_task_key}
        files = {'file' : open(file_path, 'rb')}
        return self._request('POST', 'rest/tasks/completeTask', params, files)

    def fail_task(self, scan_queue_task_id, message, scan_agent_secure_key, secure_task_key):
        """
        Marks a task as failed, to complete it without a file upload.
        :param scan_queue_task_id: ID for the Scan Agent Task to mark as failed
        :param message: The message to provide reason for failure
        :param scan_agent_secure_key: A Secure Scan Agent Key obtained from the “Request Scan Agent Key” call
        :param secure_task_key: The Secure Task Key that was returned when the Task was assigned from the queue
        """
        params = {'scanQueueTaskId' : scan_queue_task_id,  'message' : message, 'scanAgentSecureKey' : scan_agent_secure_key, 'secureTaskKey' : secure_task_key}
        return self._request('POST', 'rest/tasks/failTask', params)

    def get_scan_agent_scanners(self):
        """
        Retrieves the list of scanners that can be configured with the Scan Agent
        """
        return self._request('GET', 'rest/tasks/scanners')

    #Vulnerabilities

    def vulnerability_search(self, generic_vulnerabilities=None, teams=None, applications=None, channel_types=None, generic_severities=None, number_vulnerabilities=None,
                            page=None, parameter=None, path=None, start_date=None, end_date=None, show_open=None, show_closed=None, show_false_positive=None, 
                            show_not_false_positive=None, show_hidden=None, show_not_hidden=None, show_exploitable=None, show_not_exploitable=None, show_contested=None, 
                            show_not_contested=None, show_verified=None, show_not_verified=None, number_merged=None, show_defect_present=None, show_defect_not_present=None, 
                            show_defect_open=None, show_defect_closed=None, show_inconsistent_closed_defect_needs_scan=None, show_inconsistent_closed_defect_open_in_scan=None,
                            show_inconsistent_open_defect=None, include_custom_text=None, show_comment_present=None, comment_tags=None, days_old_modifier=None,
                            days_old=None, days_old_comments_modifier=None, days_old_comments=None, hours_old_comments_modifier=None, hours_old_comments=None, 
                            commented_by_user=None, vulnerabilities=None, cves_list=None, export_type=None, tags=None, vuln_tags=None, defect_id=None,
                            native_id=None, assign_to_user=None, show_shared_vuln_found=None, show_shared_vuln_not_found=None):
        """
        Returns a filtered list of vulnerabilities
        :param generic_vulnerabilities: Serialized list of generic vulnerability IDs to narrow results to
        :param teams: Serialized list of team IDs to narrow search to
        :param applications: Serialized list of application IDs to narrow search to
        :param channel_types: Serialized list of scanner names to narrow search to
        :param generic_severities: Serialized list of generic severity values to narrow search to
        :param number_vulnerabilities: Number of vulnerabilities to return defaults to 10
        :param page: Which page of vulnerabilities to return with each page containing {number_vulnerabilities} to return
        :param parameter: Filter to only return vulnerabilities containing this string in their parameters
        :param path: Filter to only return vulnerabilities containing this String in their path
        :param start_date: Lower bound on scan dates. Format: yyyy-MM-dd or Epoch time (in milliseconds)
        :param end_date: Upper bound on scan dates. Format: yyyy-MM-dd or Epoch time (in milliseconds)
        :param show_open: Flag to show only open vulnerabilites
        :param show_closed: Flag to show only close vulnerabilities
        :param show_false_positive: Flag to show only vulnerabilities that are false positives
        :param show_not_false_positive: Flag to show only vulnerabilities that are not false positives
        :param show_hidden: Flag to show hidden vulnerabilities
        :param show_not_hidden: Flag to show only vulnerabilities that are not hidden
        :param show_exploitable: Flag to show only vulnerabilities that are exploitable
        :param show_not_exploitable: Flag to show only vulnerabilities that are not exploitable
        :param show_contested: Flag to show only vulnerabilities that are contested
        :param show_not_contested: Flag to show only vulnerabilities that are not contested
        :param show_verified: Flag to show only verified vulnerabilities
        :param show_not_verified: Flag to show only not verified vulnerabilities
        :param number_merged: Number of vulnerabilities merged from different scans to narrow search to
        :param show_defect_present: Flag to show vulnerabilities with defects
        :param show_defect_not_present: Flag to show vulnerabilities without defects
        :param show_defect_open: Flag to show vulnerabilities with open defects
        :param show_defect_closed: Flag to show vulnerabilities with closed defects
        :param show_inconsistent_closed_defect_needs_scan: Flag to show vulnerabilities that have closed defects but have not yet been closed by a scan
        :param show_inconsistent_closed_defect_open_in_scan: Flag to show vulnerabilities that have closed defects but were found open in a scan since the defect was closed
        :param show_inconsistent_open_defect: Flag to show vulnerabilities that have open defects but have been closed by scans
        :param include_custom_text: Set to true to include Custom CWE Text in the response for each vulnerability
        :param show_comment_present: Flag to show vulnerabilities with comments
        :param comment_tags: Serialized list of comment tags. Example: commentTags[0].id=1
        :param days_old_modifier: Should only be value of "less" or "more". Used in conjunction with daysOld parameter
        :param days_old: Number of days in age of the vulnerability. Valid values are "10", "30", etc
        :param days_old_comments_modifier: Should only be value of "less" or "more". Used in conjunction with daysOldComments parameter
        :param days_old_comments: Number of days in age of the comment. Valid values are "10", "30", etc
        :param hours_old_comments_modifier: Should only be value of "less" or "more". Used in conjunction with hoursOldComments parameter
        :param hours_old_comments: Number of hours since comment was added to vulnerability. Valid values are "1", "10", etc
        :param commented_by_user: Filter vulnerabilities by ID of user that added comments to it
        :param vulnerabilities: Serialized list of vulnerability IDs
        :param cves_list: Serialized list of CVE IDs
        :param export_type: Type of export being performed (not case sensitive)
        :param tags: Filters to show vulnerabilities from Applications that are tagged with these application tags
        :param vuln_tags: lters to show vulnerabilities tagged with these vulnerability tags
        :param defect_id: Filters to show vulnerabilities with this defect attached
        :param native_id: Filters to show vulnerabilities with findings that have this native ID
        :param assign_to_user: Filters to show vulnerabilities that have a finding with this value in their assignToUser column
        :param show_shared_vuln_found: Filters to show only vulnerabilities that have been identified as Shared Vulnerabilities
        :param show_shared_vuln_not_found: Filters to show only vulnerabilities that have not been identified as Shared Vulnerabilities
        """
        params = {}
        if generic_vulnerabilities:
            for i in range(len(generic_vulnerabilities)):
                params['genericVulnerabilities[{}].id'.format(i)] = generic_vulnerabilities[i]
        if teams:
            for i in range(len(teams)):
                params['teams[{}].id'.format(i)] = teams[i]
        if applications:
            for i in range(len(applications)):
                params['applications[{}].id'.format(i)] = applications[i]
        if channel_types:
            for i in range(len(channel_types)):
                params['channelTypes[{}].name'.format(i)] = channel_types[i]
        if generic_severities:
            for i in range(len(generic_severities)):
                params['genericSeverities[{}].intValue'.format(i)] = generic_severities[i]
        if number_vulnerabilities:
            params['numberVulnerabilities'] = number_vulnerabilities
        if page:
            params['page'] = page
        if parameter:
            params['parameter'] = parameter
        if path:
            params['path'] = path
        if start_date:
            params['startDate'] = start_date
        if end_date:
            params['endDate'] = end_date
        if show_open:
            params['showOpen'] = show_open
        if show_closed:
            params['showClosed'] = show_closed
        if show_false_positive:
            param['showFalsePositive'] = show_false_positive
        if show_not_false_positive:
            param['showNotFalsePositive'] = show_not_false_positive
        if show_hidden:
            params['showHidden'] = show_hidden
        if show_not_hidden:
            params['showNotHidden'] = show_not_hidden
        if show_exploitable:
            params['showExploitable'] = show_exploitable
        if show_not_exploitable:
            params['showNotExploitable'] = show_not_exploitable
        if show_contested:
            params['showContested'] = show_contested
        if show_not_contested:
            params['showNotContested'] = show_not_contested
        if show_verified:
            params['showVerified'] = show_verified
        if show_not_verified:
            params['showNotVerified'] = show_not_verified
        if number_merged:
            params['numberMerged'] = number_merged
        if show_defect_present:
            params['showDefectPresent'] = show_defect_present
        if show_defect_not_present:
            params['showDefectNotPresent'] = show_defect_not_present
        if show_defect_open:
            params['showDefectOpen'] = show_defect_open
        if show_defect_closed:
            params['showDefectClosed'] = show_defect_closed
        if show_inconsistent_closed_defect_needs_scan:
            params['showInconsistentClosedDefectNeedsScan'] = show_inconsistent_closed_defect_needs_scan
        if show_inconsistent_closed_defect_open_in_scan:
            params['showInconsistentClosedDefectOpenInScan'] = show_inconsistent_closed_defect_open_in_scan
        if show_inconsistent_open_defect:
            params['showInconsistentOpenDefect'] = show_inconsistent_open_defect
        if include_custom_text:
            params['includeCustomText'] = include_custom_text
        if show_comment_present:
            params['showCommentPresent'] = show_comment_present
        if comment_tags:
            for i in range(len(comment_tags)):
                params['commentTags[{}].id'.format(i)] = comment_tags[i]
        if days_old_modifier:
            params['daysOldModifier'] = days_old_modifier
        if days_old:
            params['daysOld'] = days_old
        if days_old_comments_modifier:
            params['daysOldCommentsModifier'] = days_old_comments_modifier
        if days_old_comments:
            params['daysOldComments'] = days_old_comments
        if hours_old_comments_modifier:
            params['hoursOldCommentsModifier'] = hours_old_comments_modifier
        if hours_old_comments:
            params['hoursOldComments'] = hours_old_comments
        if commented_by_user:
            params['commentedByUser'] = commented_by_user
        if vulnerabilities:
            for i in range(len(vulnerabilities)):
                params['vulnerabilities[{}].id'.format(i)] = vulnerabilities[i]
        if cves_list:
            for i in range(len(cves_list)):
                params['cvesList[{}].CVE'.format(i)] = cves_list[i]
        if export_type:
            params['exportType'] = export_type
        if tags:
            for i in range(len(tags)):
                params['tags[{}].id'.format(i)] = tags[i]
        if vuln_tags:
            for i in range(len(vuln_tags)):
                params['vulnTags[{}].id'.format(i)] = vuln_tags[i]
        if defect_id:
            params['defectId'] = defect_id
        if native_id:
            params['nativeId'] = native_id
        if assign_to_user:
            params['assignToUser'] = assign_to_user
        if show_shared_vuln_found:
            params['showSharedVulnFound'] = show_shared_vuln_found
        if show_shared_vuln_not_found:
            params['showSharedVulnNotFound'] = show_shared_vuln_not_found
        return self._request('POST', 'rest/vulnerabilities', params)

    def add_comment_to_vulnerability(self, vuln_id, comment, comment_tag_ids=None):
        """
        Adds a comment to the vulnerability with the given vulnId
        :param vuln_id: Vulnerability identifier
        :param comment: The message for the comment
        :param comment_tag_ids: A comma-separated list of the Ids for any comment tags you want to attach to the comment
        """
        params = {'comment' : comment}
        if comment_tag_ids:
            params['commentTagIds'] = comment_tag_ids
        return self._request('POST', 'rest/vulnerabilities/' + str(vuln_id) + '/addComment')

    def list_severities(self):
        """
        Returns a list of severity levels in ThreadFix and their custom names
        """
        return self._request('GET', 'rest/severities')
    
    def update_vulnerability_severity(self, vulnerability_id, severity_name):
        """
        Changes the severity of the specified vulnerability to the specified severity
        :param vulnerability_id: Vulnerability identifier
        :param severity_name: Name of severity that the vulnerability is being changed to
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/severity/' + str(severity_name))

    def close_vulnerabilities(self, vulnerability_id):
        """
        Closes the specified vulnerability
        :param vulnerability_id: Vulnerabilities' identifiers
        """
        params = {'vulnerabilityIds' : vulnerability_id}
        return self._request('POST', 'rest/vulnerabilities/close', params)
        
    def get_document_attached_to_a_vulnerability(self, document_id):
        """
        Displays content of document files
        :param document_id: Document identifier
        """
        return self._request('GET', 'rest/documents/' + str(document_id) + '/download')

    def attach_file_to_vulnerability(self, vuln_id, file_path, new_file_name=None):
        """
        Attaches a file to a vulnerability
        :param vuln_id: Vulnerability identifier
        :param file_path: Path to the file you want to attach to the vulnerability
        :param new_file_name: A name to override the filename when it is attached to the vulnerability
        """
        params = {}
        if new_file_name:
            params['filename'] = new_file_name
        files = {'file' : open(file_path, 'rb')}
        return self._request('POST',  'rest/documents/vulnerabilities/' + str(vuln_id) + '/upload', params, files)

    def mark_vulnerability_as_false_positive(self, vulnerability_id):
        """
        Marks the specified vulnerability as a false positive
        :param vulnerability_id: Vulnerability identifier
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/setFalsePositive')

    def add_tag_to_vulnerability(self, vulnerability_id, tag_id):
        """
        Adds specified tag to specified vulnerability
        :param vulnerability_id: Vulnerability identifier
        :param tag_id: Tag identifier
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/tags/add/' + str(tag_id))

    def remove_tag_to_vulnerability(self, vulnerability_id, tag_id):
        """
        Removes specified tag to specified vulnerability
        :param vulnerability_id: Vulnerability identifier
        :param tag_id: Tag identifier
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/tags/remove/' + str(tag_id))

    def list_vulnerabilities_for_a_tag(self, tag_id):
        """
        Returns a list of all vulnerabilities associated with a tag
        :params tag_id: Tag identifier
        """
        return self._request('GET', 'rest/tags/' + str(tag_id) + '/listVulnerabilities')

    def mark_vulnerability_as_exploitable(self, vulnerability_id):
        """
        Change the specified vulnerability to exploitable
        :param vulnerability_id: Vulnerability identifer
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/setExploitable')

    def mark_vulnerability_as_contested(self, vulnerability_id):
        """
        Change the specified vulnerability to contested
        :param vulnerability_id: Vulnerability identifer
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/setContested')

    def mark_vulnerability_as_verified(self, vulnerability_id):
        """
        Change the specified vulnerability to verified
        :param vulnerability_id: Vulnerability identifer
        """
        return self._request('POST', 'rest/vulnerabilities/' + str(vulnerability_id) + '/setVerified')

    def get_defect_details(self, defect_id):
        """
        Returns details about the selected defect
        :param defect_id: Defect identifier
        """
        return self._request('GET', 'rest/defects/' + str(defect_id))
    
    def defect_search(self, paging=None, max_results=None, days_old=None, hours_old=None, aging_modifier=None, aging_date_type=None, start_date=None, end_date=None,
                        status_updated_start_date=None, status_updated_end_date=None, defects=None, application_defect_tracker=None, statuses=None, show_active=None,
                        show_open=None, show_closed=None):
        """
        Returns a filtered list of defects
        :param paging: By default defects are displayed 10 to a page. Changing this value will allow user to display the next set of 10 defects and so on
        :param max_results: Maximum number of defects to be returned. By default this method will only return up to 10 defects
        :param days_old: Age in days of defect(s)
        :param hours_old: Age in hours of defect(s)
        :param aging_modifier: 	Applies modifier to either daysOld or hoursOld parameter. Accepted values are "less" and "more"
        :param aging_date_type: Entering "created" will apply the search to the defect created date. Entering "status" will apply the search to the defect status updated date
        :param start_date: Lower bound on defect dates. Format: yyyy-MM-dd or Epoch time (in milliseconds)
        :param end_date: Upper bound on defect dates. Format: yyyy-MM-dd or Epoch time (in milliseconds)
        :param status_updated_start_date: Lower bound on defect updated dates. Format: yyyy-MM-dd or Epoch time (in milliseconds)
        :param status_updated_end_date: Upper bound on defect updated dates. Format: yyyy-MM-dd or Epoch time (in milliseconds)
        :param defects: Serialized list of defects by id
        :param application_defect_tracker: Serialized list of application defect trackers by id
        :param statuses: Serialized list of defects by status
        :param show_active: Flag to show only active defects
        :param show_open: Flag to show only open defects
        :param show_closed: Flag to show only closed defects
        """
        params = {}
        if paging:
            params['paging'] = paging
        if max_results:
            params['maxResults'] = max_results
        if days_old:
            params['daysOld'] = days_old
        if hours_old:
            params['hoursOld'] = hours_old
        if aging_modifier:
            params['agingModifier'] = aging_modifier
        if aging_date_type:
            params['agingDateType'] = aging_date_type
        if start_date:
            params['startDate'] = start_date
        if end_date:
            params['endDate'] = end_date
        if status_updated_start_date:
            params['statusUpdatedStartDate'] = status_updated_start_date
        if status_updated_end_date:
            params['statusUpdatedEndDate'] = status_updated_end_date
        if defects:
            for i in range(len(defects)):
                params['defects[{}].id'.format(i)] = defects[i]
        if application_defect_tracker:
            for i in range(len(application_defect_tracker)):
                params['applicationDefectTracker[{}].id'.format(i)] = application_defect_tracker[i]
        if statuses:
            for i in range(len(statuses)):
                params['statuses[{}].status'.format(i)] = statuses[i]
        if show_active:
            params['showActive'] = show_active
        if show_open:
            params['showOpen'] = show_open
        if show_closed:
            params['showClosed'] = show_closed
        return self._request('POST', 'rest/defects/search', params)

    #Web Application Firewalls (WAFs)

    def create_waf(self, name, WAFtype):
        """
        Creates a WAF with the given name and type
        :param name: Name for the WAF
        :param WAFtype: Type of WAF you are creating
        """
        params = {'name' : name, 'type' : WAFtype}
        return self._request('POST', 'rest/wafs/new', params)

    def get_waf_by_id(self, waf_id):
        """
        Gets a WAF by the WAFId
        :param waf_id: WAF identifier
        """
        return self._request('GET', 'rest/wafs/' + str(waf_id))

    def get_waf_by_name(self, waf_name):
        """
        Gets a WAF by its name
        :param waf_name: The name of the WAF being gotten
        """
        return self._request('GET', 'rest/wafs/lookup?name=' + str(waf_name))

    def get_all_wafs(self):
        """
        Gets all WAFs in the system
        """
        return self._request('GET', 'rest/wafs')

    def get_waf_rules(self, waf_id, app_id):
        """
        Returns the WAF rule text for one or all applications a WAF is attached to. If the appId is -1, it will get rules for all apps. 
        If the appId is a valid application ID, rules will be generated for that application.'
        :param waf_id: WAF identifier
        :param app_id: Application identifier
        """
        return self._request('GET', 'rest/wafs/' + str(waf_id) + '/rules/app/' + str(app_id))

    def upload_waf_log(self, waf_id, file_path):
        """
        Uploads WAF log
        :param waf_id: WAF identifier
        :param file_path: Path to file to be uploaded
        """
        files = {'file' : open(file_path, 'rb')}
        return self._request('POST', 'rest/wafs/' + str(waf_id) + '/uploadLog', files=files)

    # Utility

    def _request(self, method, url, params=None, files=None):
        """Common handler for all HTTP requests."""
        if not params:
            params = {}

        headers = {
            'Accept': 'application/json',
            'Authorization': 'APIKEY ' + self.api_key
        }

        try:
            if self.debug:
                print(method + ' ' + self.host + url)
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
