__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2021 Coalfire"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class ProviderAPI(API):

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

    def create_new_provider_type(self, name):
        """
        Creates a new type of provider with provided name
        :param name: Name of new provider type
        """
        params = { 'name' : name }
        return super().request('POST', '/api/provider/types', params=params)

    def fetch_all_provider_types(self, page=1, limit=50, href=None):
        """
        Fetches all provider types one page at a time of limit 
        :param page: The page of the provider types to get (optional if you have href)
        :param limit: The amount of provider types per page
        :param href: The link to the next page in the system from a previous call
        """
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/provider' + href)
        # First call
        return super().request('GET', f'/api/provider/types?_page={page}&_limit={limit}')

    def find_provider_type_by_id(self, provider_type_id):
        """
        Gets a specific provider type by id.
        :param provider_type_id: ID of the provider type to get
        """
        return super().request('GET', f'/api/provider/types/{provider_type_id}')

    def update_existing_provider_type(self, provider_type_id, name):
        """
        Updates an existing provider
        :param provider_type_id: ID of the provider type to change
        :param name: Name to update to 
        """
        params = { 'name' : name }
        return super().request('PUT', f'/api/provider/types/{provider_type_id}', params=params)

    def delete_provider_type(self, provider_type_id):
        """
        Deletes a specific provider type
        :param provider_type_id: ID of the provider type to delete
        """
        return super().request('DELETE', f'/api/provider/types/{provider_type_id}')

    def add_provider(self, name, provider_type, authentication_values):
        """
        Creates a new provider
        :param name: Name of provider
        :param provider_type: Type of provider
        :param authentication_values: Authentication Values (array of objects)
        """
        params = { 'name' : name, 'providerType' : provider_type, 'authenticationValues' : authentication_values}
        return super().request('POST', '/api/provider/scanners', params=params)

    def get_all_providers(self, page=1, limit=50, href=None):
        """
        Fetches all provider  one page at a time of limit 
        :param page: The page of the provider types to get (optional if you have href)
        :param limit: The amount of provider types per page
        :param href: The link to the next page in the system from a previous call
        """
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/provider' + href)
        # First call
        return super().request('GET', f'/api/provider/scanners?_page={page}&_limit={limit}')

    def find_provider_by_id(self, provider_id):
        """
        Gets a provider by its ID
        :param provider_id: ID of provider to get
        """
        return super().request('GET', f'/api/provider/scanners/{provider_id}')

    def update_existing_provider(self, provider_id, name, provider_type, authentication_values):
        """
        Updates an existing provider
        :param provider_id: ID of provider to get
        :param name: Name of provider
        :param provider_type: Type of provider
        :param authentication_values: Authentication Values (array of objects)
        """
        params = { 'name' : name, 'providerType' : provider_type, 'authenticationValues' : authentication_values}
        return super().request('PUT', f'/api/provider/scanners/{provider_id}', params=params)

    def delete_provider_by_id(self, provider_id):
        """
        Deletes a provider by its ID
        :param provider_id: ID of provider to delete
        """
        return super().request('DELETE', f'/api/provider/scanners/{provider_id}')

    def add_scheduler(self, provider_id, frequency, schedule_type, name=None, schedule_time=None, cron_expression=None):
        """
        Creates a new scheduler for scans
        :param provider_id: ID of provider to connect scheduler to
        :param frequency: frequency of scans
        :param schedule_type: What action occurs on scheduler scan or import
        :param name: Name of scheduler
        :param schedule_time: Time to do scan or import
        :param cron_expression: Cron expression representing when to do scan or import
        """
        params = { 'providerId' : provider_id, 'frequency' : frequency, 'scheduleType' : schedule_type }
        if name:
            params['name'] = name
        if schedule_time:
            params['scheduleTime'] = schedule_time
        if cron_expression:
            params['cronExpression'] = cron_expression
        return super().request('POST', '/api/provider/schedulers', params=params)

    def get_all_scheduled_requests(self, page=1, limit=50, href=None, schedule_type=None):
        """
        Fetches all provider  one page at a time of limit 
        :param page: The page of the provider types to get (optional if you have href)
        :param limit: The amount of provider types per page
        :param href: The link to the next page in the system from a previous call
        :param schedule_type: The type of schedule to find
        """
        params = {}
        if schedule_type:
            params['scheduleType'] = schedule_type
        # If href (calling another page gives an href tag for next page in line)
        if href:
            return super().request('GET', '/api/provider' + href, params=params)
        # First call
        return super().request('GET', f'/api/provider/schedulers?_page={page}&_limit={limit}', params=params)

    def find_scheduler_by_id(self, scheduler_id):
        """
        Gets a scheduler by its ID
        :param scheduler_id: ID of scheduler to get
        """
        return super().request('GET', f'/api/provider/schedulers/{scheduler_id}')

    def update_existing_scheduler(self, scheduler_id, provider_id, frequency, schedule_type, id=None, dataset_id=None, created_date=None, modified_date=None, name=None,
                                schedule_time=None, cron_expression=None, day_of_week=None, day_of_month=None, month=None, last_scheduled_run=None, next_scheduled_run=None,
                                network_ids=None):
        """
        Updates an existing scheduler for scans
        :param scheduler_id: ID of scheduler to update
        :param provider_id: ID of provider to connect scheduler to
        :param frequency: frequency of scans
        :param schedule_type: What action occurs on scheduler scan or import
        :param name: Name of scheduler
        :param schedule_time: Time to do scan or import
        :param cron_expression: Cron expression representing when to do scan or import
        """
        params = { 'providerId' : provider_id, 'frequency' : frequency, 'scheduleType' : schedule_type }
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
        if schedule_time:
            params['scheduleTime'] = schedule_time
        if cron_expression:
            params['cronExpression'] = cron_expression
        if day_of_week:
            params['dayOfTheWeek'] = day_of_week
        if day_of_month:
            params['dayOfTheMonth'] = day_of_month
        if month:
            params['month'] = month
        if last_scheduled_run:
            params['lastScheduledRun'] = last_scheduled_run
        if next_scheduled_run:
            params['nextScheduledRun'] = next_scheduled_run
        if network_ids:
            params['networkIds'] = network_ids
        return super().request('PUT', f'/api/provider/schedulers/{scheduler_id}', params=params)


    def delete_scheduler(self, scheduler_id):
        """
        Deletes a scheduler by its ID
        :param scheduler_id: ID of scheduler to delete
        """
        return super().request('DELETE', f'/api/provider/schedulers/{scheduler_id}')