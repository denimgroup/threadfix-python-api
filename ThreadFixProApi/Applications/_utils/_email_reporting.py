#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Evan Schlesinger"
__copyright__ = "(C) 2019 Denim group"
__contributors__ = ["Evan Schlesinger"]
__status__ = "Production"
__license__ = "MIT"

from ...API import API

class EmailReportingAPI(API):

    def __init__(self, host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug):
        """
        Initialize a ThreadFix Pro Email Reporting API instance.
        :param host: The URL for the ThreadFix Pro server. (e.g., http://localhost:8080/threadfix/) NOTE: must include http:// TODO: make it so that it is required or implicitly added if forgotten
        :param api_key: The API key generated on the ThreadFix Pro API Key page.
        :param verify_ssl: Specify if API requests will verify the host's SSL certificate, defaults to true.
        :param timeout: HTTP timeout in seconds, default is 30.
        :param user_agent: HTTP user agent string, default is "threadfix_pro_api/[version]".
        :param cert: You can also specify a local cert to use as client side certificate, as a single file (containing
        the private key and the certificate) or as a tuple of both file’s path
        :param debug: Prints requests and responses, useful for debugging.
        """
        super().__init__(host, api_key, verify_ssl, timeout, headers, user_agent, cert, debug)

    def list_scheduled_email_reports(self):
        """
        Retrives all scheduled email reports
        """
        return super().request('GET', '/scheduledEmailReport/list')

    def create_scheduled_email_report(self, team_id, severity, frequency, day, hour, minute, period, cron_expression, scheduling_method=None):
        """
        Creates a new scheduled email report
        :param team_id: The ID for the team to attach to the report
        :param severity: The name of the severity for the report's severity threshold
        :param frequency: Must be "Weekly" or "Daily" Determines if the schedule will be everyday or only on a specified day of the week. "SELECT" method requires this
        :param day: Only used if it is on Weekly frequency. The day on which the report will execute. "SELECT" method requires this
        :param hour: The hour 1-12 for the time the report will execute. "SELECT" method requires this
        :param minute: 0, 15, 30, 45 - The minute the report will execute. "SELECT" method requires this
        :param period: "AM" or "PM" for the time the report will execute. "SELECT" method requires this
        :param cron_expression: Only if using "CRON" scheduling method. Cron expression for when it will execure
        :param scheduling_method: "CRON" or "SELECT", but will default to "SELECT"
        """
        params = {'teamIds' : team_id, 'severity' : severity, 'frequency' : frequency, 'day' : day, 'hour' : hour, 'minute' : minute, 'period' : period, 'cronExpression' : cron_expression}
        if scheduling_method:
            params['schedulingMethod'] = scheduling_method
        return super().request('POST', '/scheduledEmailReport/add', params)

    def create_scheduled_email_report(self, scheduled_email_report_id, team_id, severity, frequency, day, hour, minute, period, cron_expression, scheduling_method=None):
        """
        Creates a new scheduled email report
        :param scheduled_email_report_id: Scheduled Email Report identifier
        :param team_id: The ID for the team to attach to the report
        :param severity: The name of the severity for the report's severity threshold
        :param frequency: Must be "Weekly" or "Daily" Determines if the schedule will be everyday or only on a specified day of the week. "SELECT" method requires this
        :param day: Only used if it is on Weekly frequency. The day on which the report will execute. "SELECT" method requires this
        :param hour: The hour 1-12 for the time the report will execute. "SELECT" method requires this
        :param minute: 0, 15, 30, 45 - The minute the report will execute. "SELECT" method requires this
        :param period: "AM" or "PM" for the time the report will execute. "SELECT" method requires this
        :param cron_expression: Only if using "CRON" scheduling method. Cron expression for when it will execure
        :param scheduling_method: "CRON" or "SELECT", but will default to "SELECT"
        """
        params = {'teamIds' : team_id, 'severity' : severity, 'frequency' : frequency, 'day' : day, 'hour' : hour, 'minute' : minute, 'period' : period, 'cronExpression' : cron_expression}
        if scheduling_method:
            params['schedulingMethod'] = scheduling_method
        return super().request('PUT', '/scheduledEmailReport/' + str(scheduled_email_report_id) + '/edit', params)

    def delete_scheduled_email_report(self, scheduled_email_report_id):
        """
        Deletes a scheduled email report
        :param scheduled_email_report_id: Scheduled Email Report identifier
        """
        return super().request('DELETE', '/scheduledEmailReport/' + str(scheduled_email_report_id))

    def set_emails_for_scheduled_email_report(self, scheduled_email_report_id, emails=None):
        """
        Sets the emails attached to an existing scheduled email report
        :param scheduled_email_report_id: Scheduled Email Report identifier
        :param emails: 	The emails to attach to the Schedule Email Report.  See the example for how to attach multiple.  
                        To remove all emails from a report, make this call without providing any 'emails' parameters.
        """
        params = {}
        if emails:
            params['emails'] = emails
        return super().request('PUT', '/scheduledEmailReport/' + str(scheduled_email_report_id) + '/emails', params)

    def add_email_list_to_scheduled_email_report(self, scheduled_email_report_id, email_list_id):
        """
        Attaches an email list to a scheduled email report
        :param scheduled_email_report_id: Scheduled Email Report identifier
        :param email_list_id: Email List identifier
        """
        return super().request('POST', '/scheduledEmailReport/' + str(scheduled_email_report_id) + '/emailList/' + str(email_list_id))

    def remove_email_list_to_scheduled_email_report(self, scheduled_email_report_id, email_list_id):
        """
        Removes an email list to a scheduled email report
        :param scheduled_email_report_id: Scheduled Email Report identifier
        :param email_list_id: Email List identifier
        """
        return super().request('DELETE', '/scheduledEmailReport/' + str(scheduled_email_report_id) + '/emailList/' + str(email_list_id))

    def list_email_lists(self):
        """
        Retrieves all email lists
        """
        return super().request('GET', '/emailList/list')