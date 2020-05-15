#!/usr/bin/python
# -*- coding: utf-8 -*-

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from fireeyehelix_consts import *
import requests
import json
from bs4 import BeautifulSoup

import hashlib
import pytz
from datetime import datetime, timedelta


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class FireEyeHelixConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(FireEyeHelixConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._helix_id = None
        self._api_key = None
        self._header = None
        return

    def _flatten_response_data(self, response):
        try:
            response_data = response.get('data', {})
            response.update(response_data)
            del response['data']
        except:
            pass

        return response

    def flatten_json(self, y):
        out = {}

        def flatten(x, name=''):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '_')
            elif type(x) is list:
                i = 0
                for a in x:
                    flatten(a, name + str(i) + '_')
                    i += 1
            else:
                out[name[:-1]] = x

        flatten(y)
        return out

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(
            status_code, error_text)

        message = message.replace(u'{', '')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(
                        str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts
        self.debug_print("kwargs", kwargs)
        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint.format(helix_id=self._helix_id)
        # self.debug_print("URL", url)
        self.save_progress("Executing against URL: {}".format(url))

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                headers=self._header,
                **kwargs
            )
        except Exception as e:
            self.save_progress("EXCEPTION: {}".format(str(e)))
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(
                        str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used test connectivity to Akamai
        :param param: Dictionary of input parameters
        :return: status success/failure
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        endpoint = FIREEYEHELIX_CONN_TEST

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")

        return action_result.set_status(phantom.APP_SUCCESS), response

    def _handle_on_poll(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(
            self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Get the config to get timezone parameter
        config = self.get_config()

        # If timezone is not set then cancel. We need the timezone to set the correct query times for ingestion.
        try:
            tz = config.get('timezone')
        except:
            return action_result.set_status(phantom.APP_ERROR, "Asset configuration timezone is not set.")

        # If it is a manual poll or first run, ingest data from the last 1 hour
        if self.is_poll_now() or self._state.get('first_run', True):
            start_time = datetime.now(pytz.timezone(tz)) - timedelta(hours=1)

        # If it is a scheduled poll, ingest from last_ingestion_time
        else:
            start_time = self._state.get('last_ingestion_time', datetime.now(
                pytz.timezone(tz)) - timedelta(hours=1))

        # End time is current time stamp
        end_time = datetime.now(pytz.timezone(tz))

        # Print the times in an acceptable format for Fireeye
        if(type(start_time) is not str):
            start_time = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if(type(end_time) is not str):
            end_time = end_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        limit = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))

        # query parameters
        params = {"limit": limit, "created_at__gte": start_time,
                  "created_at__lte": end_time}

        endpoint = "/helix/id/{helix_id}/api/v3/alerts/"

        ret_val, alerts_list = self._make_rest_call(
            endpoint, action_result, params=params)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit
        # Add the response into the data section
        response = self._flatten_response_data(alerts_list)
        action_result.add_data(response)

        if response:

            self.save_progress('Ingesting {} alerts'.format(
                len(response['results'])))

            for alert in response['results']:

                # Create a container for each alert
                container_creation_status, container_id = self._create_container(
                    alert)

                if phantom.is_fail(container_creation_status) or not container_id:
                    self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.format(
                        container_id=container_id, error_msg=container_creation_status))
                    continue
                else:
                    # OLD Create artifacts for specific alert
                    # artifacts_creation_status, artifacts_creation_msg = self._create_artifacts(
                    #     alert=alert, container_id=container_id)
                    self.debug_print('Container ID for Creating Artifacts: {container_id}'.format(
                        container_id=container_id))
                    # NEW create artifact from alert['alert_type_details']['detail']
                    artifacts_creation_status, artifacts_creation_msg = self._create_artifact(
                        srcdata=alert, alert=alert['alert_type_details'][
                            'detail'], container_id=container_id, artifact_name=alert["message"],
                        artifact_severity=alert["severity"], artifact_category=alert["alert_type"]["category"])

                    if phantom.is_fail(artifacts_creation_status):
                        self.debug_print('Error while creating artifacts for container with ID {container_id}. {error_msg}'.format(
                            container_id=container_id, error_msg=artifacts_creation_msg))
            self.save_progress("Finished with the results")
        else:
            self.save_progress('No alerts found')

        self.save_progress("Done checking response, setting states....")

        # Store it into state_file, so that it can be used in next ingestion
        self._state['first_run'] = False
        self._state['last_ingestion_time'] = end_time

        self.save_progress(
            "CURRENT STATE(S) {}".format(json.dumps(self._state)))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _convert_timestamp_to_string(self, timestamp, tz):
        """ This function is used to handle of timestamp converstion for on_poll action.
        :param timestamp: Epoch time stamp
        :param tz: Timezone configued in the Asset
        :return: datetime string
        """

        date_time = datetime.fromtimestamp(timestamp, pytz.timezone(tz))

        return date_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def _create_container(self, alert):
        """ This function is used to create the container in Phantom using alert data.
        :param alert: Data of single alert
        :return: status(success/failure), container_id
        """
        container_dict = dict()

        container_dict['name'] = '{alert_name}'.format(
            alert_name=alert['message'])
        # CHANGE TO ALERT ID
        container_dict['source_data_identifier'] = alert["id"]
        container_dict['description'] = alert['message']
        container_dict["severity"] = alert['severity']
        container_dict['start_time'] = alert['created_at']

        container_creation_status, container_creation_msg, container_id = self.save_container(
            container=container_dict)

        if phantom.is_fail(container_creation_status):
            self.debug_print(container_creation_msg)
            self.save_progress('Error while creating container for alert {alert_name}. '
                               '{error_message}'.format(alert_name=alert['assessment'], error_message=container_creation_msg))
            return self.set_status(phantom.APP_ERROR)

        return self.set_status(phantom.APP_SUCCESS), container_id

    def _create_artifact(self, alert, container_id, artifact_name, artifact_severity=None, artifact_category=None, srcdata=None):
        """ This function is used to create artifacts in given container using alert data.
        :param alert: Data of single alert
        :param container_id: ID of container in which we have to create the artifacts
        :return: status(success/failure), message
        """

        # pudb.set_trace()
        artifacts = []
        # validate we received a dict of alert data
        if type(alert) is dict:
            # Initialize the cef and cef_types dicts
            cef = {}
            cef_types = {}

            # Loop through the keys in the alert dict
            for alert_key in alert.keys():
                # if a cef mapping is found matching our key rename and check if
                # there are cef_contains to associate with the cef key
                if FIREEYEHELIX_CEF_MAPPING.get(alert_key):
                    # remap using the cef_name field if exists
                    if FIREEYEHELIX_CEF_MAPPING[alert_key].get("cef_name"):
                        cef[FIREEYEHELIX_CEF_MAPPING[alert_key]
                            ["cef_name"]] = alert[alert_key]
                    else:
                        cef[alert_key] = alert[alert_key]
                    # if cef_contains is defined add it to the cef_types array
                    if FIREEYEHELIX_CEF_MAPPING[alert_key].get("cef_contains"):
                        cef_types[FIREEYEHELIX_CEF_MAPPING[alert_key]["cef_name"]
                                  ] = FIREEYEHELIX_CEF_MAPPING[alert_key]["cef_contains"]
                # if we didn't find a matching key add it as it is to the cef dict
                else:
                    cef[alert_key] = alert[alert_key]

            # build the artifact to be created
            artifact = {
                "container_id": container_id,
                'name': artifact_name,
                'description': "Artifact created by FireEye Helix app",
                'type': artifact_category,
                'severity': artifact_severity,
                "cef": cef,
                "cef_types": cef_types
            }

            # if the raw incident data is passed append it as data (which is not displayed but available on artifact export)
            if srcdata:
                artifact['data'] = srcdata

            # generate a unique hash from this artifact contents to keep from duplicating artifacts per container
            artifact['source_data_identifier'] = self._create_dict_hash(
                artifact)

            artifacts.append(artifact)

            # save the artifact ()
            create_artifact_status, create_artifact_msg, _ = self.save_artifacts(
                artifacts)

        if phantom.is_fail(create_artifact_status):
            return self.set_status(phantom.APP_ERROR), create_artifact_msg

        return self.set_status(phantom.APP_SUCCESS), 'Artifacts created successfully'

    def _create_dict_hash(self, input_dict):
        """ This function is used to generate the hash from dictionary.
        :param input_dict: Dictionary for which we have to generate the hash
        :return: hash
        """
        if not input_dict:
            return None

        try:
            input_dict_str = json.dumps(
                input_dict, sort_keys=True).encode('utf-8')
        except Exception as e:
            self.debug_print('Handled exception in _create_dict_hash', e)
            return None

        return hashlib.md5(input_dict_str).hexdigest()

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        if action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)
        elif action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        if type(self._state) is not dict:
            self._state = {}

        self.save_progress(
            "Initialized current state: {}".format(json.dumps(self._state)))

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._helix_id = config.get('helix_id')
        self._api_key = config.get('api_key')
        self._header = {
            'accept': 'application/json',
            'x-fireeye-api-key': self._api_key
        }

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.debug_print("STATE BEFORE SAVE STATE", self._state)
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    # import pudb
    import argparse

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = FireEyeHelixConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False,
                               data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = FireEyeHelixConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
