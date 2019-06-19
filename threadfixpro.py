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

    def list_teams(self):
        """Retrieves all the teams."""
        return self._request('GET', 'rest/teams')

    def get_team_by_id(self, team_id):
        """Retrieves team with id of team_id"""
        return self._request('GET', 'rest/teams/{}'.format(team_id))

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
            files= [{'file' : open(file_path)} for file_path in file_paths]
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
