__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class DefectTrackerAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080) NOTE: must include http:// 
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param headers: Headers are done automatically so feel free to leave this as None unless you really need custom headers
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        super().__init__(host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)

    def test_defect_tracker_connection(self, name, provider_type, authentication_values):
        """
        Tests connection to the defect tracker
        :param name: Name of defect tracker
        :param provider_type: Provider type of defect tracker
        :param authentication_values: Authentication values for defect tracker.
        """
        params = {}
        if name:
            params['name'] = name
        if provider_type:
            params['providerType'] = provider_type
        if authentication_values:
            params['authenticationValues'] = authentication_values
        return super().request('POST', '/api/defect-tracker/test-connection', params=params)

    def get_projects_for_defect_tracker(self, defect_tracker_id):
        """
        Gets all projects for a specific defect tracker
        :param defect_tracker_id: ID of defect tracker to get projects from
        """
        return super().request('GET', f'/api/defect-tracker/{defect_tracker_id}/projects')


    def get_list_of_fields_for_defect_tracker_project_issue(self, defect_tracker_id, project_native_id, issue_type_id):
        """
        Gets a list of fields describing the project issue
        :param defect_tracker_id: ID of defect tracker
        :param project_native_id: Native ID of project 
        :param issue_type_id: ID of issue type
        """
        return super().request('GET', f'/api/defect-tracker/{defect_tracker_id}/projects/{project_native_id}/fields/{issue_type_id}')

    def get_suggested_type_ahead_values_for_defect_tracker_fields(self, defect_tracker_id, native_id=None, name=None, active=None, multiple=None, required=None, visible=None, 
                                                                readonly=None, type_ahead_field=None, type_ahead_endpoint=None, type_ahead_accepted_type=None,
                                                                value=None, field_type=None):
        """
        Gets suggested values for defect tracker fields
        :param defect_tracker_id: ID of defect tracker
        :param native_id: Native ID of type ahead data
        :param name: Name of type ahead data.
        :param active: Active state of type ahead data
        :param multiple: If type ahead data is multiple
        :param required: If type ahead data is required
        :param visible: If type ahead data is visiblle
        :param readonly: If type ahead data is readonly
        :param type_ahead_field: Type ahead field
        :param type_ahead_endpoint: Type ahead endpoint
        :param type_ahead_accepted_type: Accepted types for the type ahead
        :param value: value of type ahead
        :param field_type: field type of type ahead
        """
        params = {}
        if native_id:
            params['nativeId'] = native_id
        if name:
            params['name'] = name
        if active != None:
            params['active'] = active
        if multiple != None:
            params['multiple'] = multiple
        if required != None:
            params['required'] = required
        if visible != None:
            params['visible'] = visible
        if readonly != None:
            params['readonly'] = readonly
        if type_ahead_field:
            params['typeAheadField'] = type_ahead_field
        if type_ahead_endpoint:
            params['typeAheadEndpoint'] = type_ahead_endpoint
        if type_ahead_accepted_type:
            params['typeAheadAcceptedType'] = type_ahead_accepted_type
        if value:
            params['value'] = value
        if field_type:
            params['fieldType'] = field_type
        return super().request('POST', f'/api/defect-tracker/{defect_tracker_id}/type-ahead-data', params=params)

    def submit_defect(self, defect_tracker_id, project_id=None, issue_type_id=None, vulnerabilties=None):
        """
        Adds a new defect to the defect tracker.
        :param defect_tracker_id: ID of defect tracker to add defect to.
        :param project_id: ID of project defect belongs to.
        :param issue_type_id: Type of issue the defect is.
        :param vulnerabilties: Vulnerabilities related to defect.
        """
        params = {}
        if project_id:
            params['projectId'] = project_id
        if issue_type_id:
            params['issueTypeId'] = issue_type_id
        if vulnerabilties:
            params['vulnerabilities'] = vulnerabilties
        return super().request('POST', f'/api/defect-tracker/{defect_tracker_id}/submit', params=params)

    def sync_defect(self, defect_id, defect_tracker_id):
        """
        Syncs defect with its defect tracker if it has become disconnected
        :param defect_id: ID of defect to sync
        :param defect_tracker_id: ID of defect tracker to sync to.
        """
        return super().request('PATCH', f'/api/defect-tracker/{defect_tracker_id}/defects/{defect_id}/sync')

    def generate_field_mapping(self, defect_tracker_id, project_id=None, defect_type_id=None, profile_id=None, vuln_ids=None):
        """
        Generates a new field mapping
        :param defect_tracker_id:
        :param project_id:
        :param defect_type_id:
        :param profile_id: Profile attached to field mapping
        :param vuln_ids: List of vulnerability ids for field mapping
        """
        params = {}
        if project_id:
            params['projectId'] = project_id
        if defect_type_id:
            params['defectTypeId'] = defect_type_id
        if profile_id:
            params['profileId'] = profile_id
        if vuln_ids:
            params['vulnIds'] = vuln_ids
        return super().request('POST', f'/api/defect-tracker/{defect_tracker_id}/generate-field-mappings')

    def add_defect_tracker(self, name, provider_type, authentication_values):
        """
        Creates a new defect trackers
        :param name: Name of defect tracker
        :param provider_type: Type of defect tracker
        :param authentication_values: Authentication information for defect tracker
        """
        params = { 'name' : name, 'providerType' : provider_type, 'authenticationValues' : authentication_values}
        return super().request('POST', '/api/provider/defect-trackers', params=params)

    def get_all_defect_trackers(self, page=1, limit=50, href=None):
        """
        Fetches all defect trackers one page at a time of limit 
        :param page: The page of the defect trackers to get (optional if you have href)
        :param limit: The amount of defect trackers per page
        :param href: The link to the next page in the system from a previous call
        """
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/provider' + href)
        # First call
        return super().request('GET', f'/api/provider/defect-trackers?_page={page}&_limit={limit}')

    def find_defect_tracker_by_id(self, defect_tracker_id):
        """
        Gets defect tracker by id
        :param defect_tracker_id: ID of defect tracker to get
        """
        return super().request('GET', f'/api/provider/defect-trackers/{defect_tracker_id}')

    def update_existing_defect_tracker(self, defect_tracker_id, name, provider_type, authentication_values):
        """
        Updates an existing defect trackers
        :param defect_tracker_id: ID of defect tracker to update
        :param name: Name of defect tracker
        :param provider_type: Type of defect tracker
        :param authentication_values: Authentication information for defect tracker
        """
        params = { 'name' : name, 'providerType' : provider_type, 'authenticationValues' : authentication_values}
        return super().request('POST', f'/api/provider/defect-trackers/{defect_tracker_id}', params=params)

    def delete_defect_tracker(self, defect_tracker_id):
        """
        Deletes defect tracker
        :param defect_tracker_id: ID of defect tracker to delete
        """
        return super().request('DELETE', f'/api/provider/defect-trackers/{defect_tracker_id}')

    def add_defect_tracker_profile(self, id=None, dataset_id=None, created_date=None, modified_date=None, name=None, project_id=None, issue_type_id=None, profile_fields=None):
        """
        Creates a new defect tracker profile
        :param id: ID of profile
        :param dataset_id: ID of dataset related to profile
        :param created_date: Created date of defect tracker profile
        :param modified_date: Modified date of defect tracker profile
        :param name: Name of profile
        :param project_id: ID of project related to profile
        :param issue_type_id: ID of issue type of this profile
        :param profile_fields: Fields that the profile contains
        """
        params = {}
        if id:
            params['id'] = id
        if dataset_id:
            params['datasetId'] = dataset_id
        if created_date:
            params['createdDate'] = created_date
        if modified_date:
            params['modifiedDate'] = modified_date
        if name:
            params['name'] = name
        if project_id:
            params['projectId'] = project_id
        if issue_type_id:
            params['issueTypeId'] = issue_type_id
        if profile_fields:
            params['profileFields'] = profile_fields
        return super().request('POST', '/api/provider/defect-profiles', params=params)

    def get_all_defect_profiles(self, page=1, limit=50, href=None):
        """
        Fetches all defect profiles one page at a time of limit 
        :param page: The page of the defect profiles to get (optional if you have href)
        :param limit: The amount of defect profiles per page
        :param href: The link to the next page in the system from a previous call
        """
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/provider' + href)
        # First call
        return super().request('GET', f'/api/provider/defect-profiles?_page={page}&_limit={limit}')

    def get_defect_profile_by_id(self, defect_profile_id):
        """
        Gets a defect profile by its ID
        :param defect_profile_id: ID of the defect profile to get
        """
        return super().request('GET', f'/api/provider/defect-profiles/{defect_profile_id}')

    def update_defect_tracker_profile(self, defect_profile_id, id=None, dataset_id=None, created_date=None, modified_date=None, name=None, project_id=None, issue_type_id=None, profile_fields=None):
        """
        Updates an existing defect tracker profile
        :param defect_profile_id: ID of defect profile to update
        :param id: ID of profile
        :param dataset_id: ID of dataset related to profile
        :param created_date: Created date of defect tracker profile
        :param modified_date: Modified date of defect tracker profile
        :param name: Name of profile
        :param project_id: ID of project related to profile
        :param issue_type_id: ID of issue type of this profile
        :param profile_fields: Fields that the profile contains
        """
        params = {}
        if id:
            params['id'] = id
        if dataset_id:
            params['datasetId'] = dataset_id
        if created_date:
            params['createdDate'] = created_date
        if modified_date:
            params['modifiedDate'] = modified_date
        if name:
            params['name'] = name
        if project_id:
            params['projectId'] = project_id
        if issue_type_id:
            params['issueTypeId'] = issue_type_id
        if profile_fields:
            params['profileFields'] = profile_fields
        return super().request('PUT', f'/api/provider/defect-profiles/{defect_profile_id}', params=params)


    def delete_defect_profile(self, defect_profile_id):
        """
        Delets a defect profile 
        :param defect_profile_id: ID of the defect profile to delete
        """
        return super().request('DELETE', f'/api/provider/defect-profiles/{defect_profile_id}')