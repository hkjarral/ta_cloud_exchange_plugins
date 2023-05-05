import json
import requests
import jsonpath

# Set up the API credentials and URL
api_username = 'api_18b1781ffa42d0779'
api_password = 'a4df05297bf1f2e022dfed63bd17ab814eaab7eb568631f2aa169bd8ee4f6ce0'
api_url = 'https://poc1.illum.io'
org_id = '65865'
label_id = 'aws'

# Define the headers for the API request
headers = {
    'Accept': 'application/json'
}
auth = (api_username,api_password)

# Send the API request to retrieve the workloads
response = requests.get(api_url + '/api/v2/orgs/' + org_id + '/workloads', headers=headers, auth=auth)


# Check if the API request was successful
if response.status_code == 200:

    # Parse the JSON response to extract the workloads
    json_response = json.loads(response.text)

    # Extract value of Location Label from each array of the output.
    for i in range(0,len(json_response)):
       labels = jsonpath.jsonpath(json_response[i],'labels[2].value')

       # Check if Location Label is set to "quarantine" if it is return public ip of workload
       if (labels[0]) == label_id :
           public_ip = (jsonpath.jsonpath(json_response[i],'public_ip'))
           workload_id = (jsonpath.jsonpath(json_response[i], 'href'))
           hostname = (jsonpath.jsonpath(json_response[i], 'hostname'))
           print('hostname='+hostname[0]+'  Label='+  labels[0] +'  Public-IP='+ public_ip[0] + ' Workload-ID='+workload_id[0])



    #json_string = json.dumps(json_response, indent=4)
    #print (json_string)
else:
    print('Failed to retrieve workloads. Error code:', response.status_code)