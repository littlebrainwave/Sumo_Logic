import json
import base64
import logging
import sys
import time
import urllib3
from datetime import datetime, timedelta
from urllib3 import PoolManager, encode_multipart_formdata

logging.basicConfig(filename='sumo-search-job.log', level='INFO', format='%(asctime)s %(levelname)s: %(message)s')
logging.info('*************STARTING REQUEST*************')

### READ IN ARGUMENTS ###
# The accessId for the Sumo user
access_id = 'XXX'
# The accessKey for the Sumo user
access_key = 'XXX'
# The API endpoint for your account, e.g. https://api.sumologic.com
SUMO_API_URL = 'https://api.sumologic.com'

# Calculate time ranges
current_time = datetime.now()
from_time = current_time - timedelta(minutes=2)
from_time_str = from_time.strftime('%Y-%m-%dT%H:%M:%S')
to_time_str = current_time.strftime('%Y-%m-%dT%H:%M:%S')

searchJob = {
    "query": "cat path://\"/Library/Users/USEREMAILREMOVED/Lookups/All Contractor AD Groups\"",
    "from": from_time_str,
    "to": to_time_str,
    "timeZone": "CST"
}

# Convert payload to JSON format
json_payload = json.dumps(searchJob)

# The API requires some headers be set
auth_header = f"{access_id}:{access_key}"
encoded_auth_header = base64.b64encode(auth_header.encode()).decode()
headers = {'Authorization': 'Basic %s' % encoded_auth_header, 'Content-Type': 'application/json', 'Accept': 'application/json'}

# Create a urllib3 PoolManager
http = urllib3.PoolManager()

# Takes a search job, creates it, and returns the ID.
def executesearchjob(searchjob):
    logging.info('executing searchjob: ' + json.dumps(searchjob))
    print('executing searchjob: ' + json.dumps(searchjob))
    try:
        r = http.request('POST', f"{SUMO_API_URL}/api/v1/search/jobs", body=json_payload, headers=headers)
        if r.status != 202:
            logging.error('got back status code ' + str(r.status))
            logging.error('unable to execute searchjob! ' + r.data.decode('utf-8'))
            print('Unable to execute search job! ' + str(r.status) + r.data.decode('utf-8'))
            sys.exit(1)
        else:
            response = json.loads(r.data.decode('utf-8'))
            logging.info('got back response ' + json.dumps(response))
            return response['id']
    except Exception as e:
        logging.error('Error: ' + str(e))
        print('Error: ' + str(e))
        sys.exit(1)

# Polls the search job id until it completes.  Check's the status every 5 seconds.
def pollsearchjob(searchjobid):
    logging.info('checking status of searchjob: ' + searchjobid)
    status = ''
    while status != 'DONE GATHERING RESULTS':
        try:
            r = http.request('GET', f"{SUMO_API_URL}/api/v1/search/jobs/{searchjobid}", headers=headers)
            if r.status != 200:
                logging.error('got back status code ' + str(r.status))
                logging.error('unable to check status of searchJob ' + searchjobid + '!')
                print('unable to check status of searchJob ' + searchjobid + '!' + str(r.status))
                sys.exit(1)
            else:
                response = json.loads(r.data.decode('utf-8'))
                logging.info('got back response for search job id ' + searchjobid + ' ' + json.dumps(response))
                print('Your search job id is ' + searchjobid)
                status = response['state']
                time.sleep(5)
        except Exception as e:
            logging.error('Error: ' + str(e))
            print('Error: ' + str(e))
            sys.exit(1)

# Saves search job results to a file
def save_results_to_file(searchjobid):
    url = f"{SUMO_API_URL}/api/v1/search/jobs/{searchjobid}/messages?offset=0&limit=10000"
    try:
        r = http.request('GET', url, headers=headers)
        if r.status == 200:
            with open("Contractor_AD_Users.txt", "w") as file:
                file.write(r.data.decode('utf-8'))
            logging.info("Search job results saved to Contractor_AD_Users.txt")
            print("Search job results saved to Contractor_AD_Users.txt")
        else:
            logging.error("Unable to retrieve search job results")
            print("Unable to retrieve search job results")
    except Exception as e:
        logging.error('Error: ' + str(e))
        print('Error: ' + str(e))

# Function to extract user.username field from search job results
def extract_usernames(results):
    usernames = []
    logging.info("Extracting users from Contractor_AD_Users.txt")
    print("Extracting users from Contractor_AD_Users.txt")
    for result in results['messages']:
        username = result.get('map', {}).get('user.username', '')
        if username:
            usernames.append(username)
    return usernames

# Function to save extracted usernames to a new JSON file
def save_extracted_usernames(usernames):
    entity_ids = [f"_username-{username}" for username in usernames]
    payload = {
        "criticality": "Contractors",
        "entityIds": entity_ids
    }
    with open("contractor_criticality.json", "w") as file:
        json.dump(payload, file)
    logging.info("Extracted users saved to contractor_criticality.json")
    print("Extracted users saved to contractor_criticality.json")

# Function to post extracted usernames to the specified endpoint
def post_extracted_usernames():
    endpoint_url = "https://api.sumologic.com/api/sec/v1/entities/bulk-update-criticality"
    try:
        with open("contractor_criticality.json", "r") as file:
            extracted_usernames_data = json.load(file)
        headers = {'Authorization': 'Basic %s' % encoded_auth_header, 'Content-Type': 'application/json', 'Accept': 'application/json'}
        entity_ids = extracted_usernames_data["entityIds"]
        chunked_entity_ids = [entity_ids[i:i+99] for i in range(0, len(entity_ids), 99)]
        for chunk in chunked_entity_ids:
            payload = {
                "criticality": "Contractors",
                "entityIds": chunk
            }
            payload_json = json.dumps(payload)            
            r = http.request('POST', endpoint_url, body=payload_json.encode(), headers=headers)
            if r.status == 200:
                print("Extracted usernames successfully posted to the endpoint.")
                logging.info("Extracted usernames successfully posted to the Match List.")
            else:
                logging.error("Failed to post extracted usernames to the endpoint. Status code: %s" % r.status)
                logging.error("Response: %s" % r.data.decode('utf-8'))
                print("Failed to post extracted usernames to the endpoint. Status code:", r.status)
                print("Response:", r.data.decode('utf-8'))
    except Exception as e:
        logging.error('Error: ' + str(e))
        print('Error: ' + str(e))


# We create the search job and are given back the ID
searchJobID = executesearchjob(searchJob)

# We poll the search job every 5 seconds until it is complete or fails.
pollsearchjob(searchJobID)

# Save search job results to a file
save_results_to_file(searchJobID)

# Extract usernames from search job results and save to a new JSON file
with open("Contractor_AD_Users.txt", "r") as file:
    search_results = json.load(file)
    extracted_usernames = extract_usernames(search_results)
    save_extracted_usernames(extracted_usernames)

# Post extracted usernames to the specified endpoint
post_extracted_usernames()
