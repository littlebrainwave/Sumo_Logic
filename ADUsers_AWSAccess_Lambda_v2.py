import json
import base64 
import sys
import time
import os
import boto3
import urllib3
from datetime import datetime, timedelta
from urllib3 import PoolManager, encode_multipart_formdata
from base64 import b64encode, b64decode

ENCRYPTED_ID = os.environ['api_id']
# Decrypt code should run once and variables stored outside of the function
# handler so that these are decrypted once per container
DECRYPTED_ID = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTED_ID),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')

ENCRYPTED_KEY = os.environ['api_key']
# Decrypt code should run once and variables stored outside of the function
# handler so that these are decrypted once per container
DECRYPTED_KEY = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTED_KEY),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
    )['Plaintext'].decode('utf-8')

def lambda_handler(event, context):
    
    ### READ IN ARGUMENTS ###
    # The accessId for the Sumo user
    access_id = DECRYPTED_ID
    # The accessKey for the Sumo user
    access_key = DECRYPTED_KEY
    # The API endpoint for your account, e.g. https://api.sumologic.com
    SUMO_API_URL = 'https://api.sumologic.com'

    # Calculate time ranges
    current_time = datetime.now()
    from_time = current_time - timedelta(minutes=2)
    from_time_str = from_time.strftime('%Y-%m-%dT%H:%M:%S')
    to_time_str = current_time.strftime('%Y-%m-%dT%H:%M:%S')

    searchJob = {
        "query": "cat path://\"/Library/Admin Recommended/Applications/Lookups/AD User Inventory - AWS Access\"",
        "from": from_time_str,
        "to": to_time_str,
        "timeZone": "CST"
    }

    # Convert payload to JSON format
    json_payload = json.dumps(searchJob)

    # The API requires some headers be set
    auth_header = f"{access_id}:{access_key}"
    encoded_auth_header = b64encode(auth_header.encode()).decode()
    headers = {'Authorization': 'Basic %s' % encoded_auth_header, 'Content-Type': 'application/json', 'Accept': 'application/json'}

    # Create a urllib3 PoolManager
    http = urllib3.PoolManager()

    # Takes a search job, creates it, and returns the ID.
    def executesearchjob(searchjob):
        print('executing searchjob: ' + json.dumps(searchjob))
        try:
            r = http.request('POST', f"{SUMO_API_URL}/api/v1/search/jobs", body=json_payload, headers=headers)
            if r.status != 202:
                print('Unable to execute search job! ' + str(r.status) + r.data.decode('utf-8'))
                sys.exit(1)
            else:
                response = json.loads(r.data.decode('utf-8'))
                return response['id']
        except Exception as e:
            print('Error: ' + str(e))
            sys.exit(1)

    # Polls the search job id until it completes.  Check's the status every 5 seconds.
    def pollsearchjob(searchjobid):
        status = ''
        while status != 'DONE GATHERING RESULTS':
            try:
                r = http.request('GET', f"{SUMO_API_URL}/api/v1/search/jobs/{searchjobid}", headers=headers)
                if r.status != 200:
                    print('unable to check status of searchJob ' + searchjobid + '!' + str(r.status))
                    sys.exit(1)
                else:
                    response = json.loads(r.data.decode('utf-8'))
                    print('Your search job id is ' + searchjobid)
                    status = response['state']
                    time.sleep(5)
            except Exception as e:
                print('Error: ' + str(e))
                sys.exit(1)

    # Saves search job results to a file
    def save_results_to_file(searchjobid):
        url = f"{SUMO_API_URL}/api/v1/search/jobs/{searchjobid}/messages?offset=0&limit=10000"
        try:
            r = http.request('GET', url, headers=headers)
            if r.status == 200:
                with open("/tmp/AWS_AD_Users.txt", "w") as file:
                    file.write(r.data.decode('utf-8'))
                print("Search job results saved to AWS_AD_Users.txt")
            else:
                print("Unable to retrieve search job results")
        except Exception as e:
            print('Error: ' + str(e))

    # Function to extract user.username field from search job results
    def extract_usernames(results):
        usernames = []
        print("Extracting usernames from AWS_AD_Users.txt")
        for result in results['messages']:
            username = result.get('map', {}).get('user.username', '')
            if username:
                usernames.append(username)
        return usernames

    # Function to save extracted usernames to a new JSON file
    def save_extracted_usernames(usernames):
        expiration_time = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ')
        description = "AWS Users"
        items = [{"value": username, "active": True, "expiration": expiration_time, "description": description} for username in usernames]
        data = {"items": items}
        with open("/tmp/extracted_usernames.json", "w") as file:
            json.dump(data, file, indent=4)
        print("Extracted usernames saved to extracted_usernames.json")

    # Function to post extracted usernames to the specified endpoint
    def post_extracted_usernames():
        endpoint_url = f"{SUMO_API_URL}/api/sec/v1/match-lists/28/items"
        try:
            with open("/tmp/extracted_usernames.json", "r") as file:
                extracted_usernames_data = json.load(file)
            headers = {'Authorization': 'Basic %s' % encoded_auth_header, 'Content-Type': 'application/json', 'Accept': 'application/json'}
            payload_json = json.dumps(extracted_usernames_data)            
            r = http.request('POST', endpoint_url, body=payload_json.encode(), headers=headers)
            if r.status == 200:
                print("Extracted usernames successfully posted to the endpoint.")
            else:
                print("Failed to post extracted usernames to the endpoint. Status code:", r.status)
                print("Response:", r.data.decode('utf-8'))
        except Exception as e:
            print('Error: ' + str(e))

    # We create the search job and are given back the ID
    searchJobID = executesearchjob(searchJob)

    # We poll the search job every 5 seconds until it is complete, or fails.
    pollsearchjob(searchJobID)

    # Save search job results to a file
    save_results_to_file(searchJobID)

    # Extract usernames from search job results and save to a new JSON file
    with open("/tmp/AWS_AD_Users.txt", "r") as file:
        search_results = json.load(file)
        extracted_usernames = extract_usernames(search_results)
        save_extracted_usernames(extracted_usernames)

    # Post extracted usernames to specified endpoint
    post_extracted_usernames()
    
    return {
        "statusCode": 200,
        "body": json.dumps("Script executed successfully!")
    }
