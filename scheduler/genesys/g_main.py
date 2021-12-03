import base64, requests, sys, os
import boto3
import json
import logging
import time
from boto3.dynamodb.conditions import Key

secret_name_client = "karuna_secret_key"
secret_name_token = "g_access_key"
genesys_environment = "mypurecloud.com.au"
token_url = f"https://login.{genesys_environment}/oauth/token"
skills_url = f"https://api.{genesys_environment}/api/v2/routing/skills"
agents_url = f"https://api.{genesys_environment}/api/v2/users"

region = 'ap-southeast-2'
secret_client = {}
secret_token = {}

def lambda_handler(event, context):

    try:
        init()
        token_ex_time = int(secret_token['expires_time'])
        if time.time() >  token_ex_time:
            update_token()

        if event['httpMethod'] == "GET" and event['path'] == "/agents":
            result = get_agents()
        elif event['httpMethod'] == "GET" and event['path'] == "/skills":
            result = get_skills()
        elif event['httpMethod'] == "GET" and event['path'] == "/update_token":
            result = update_token()
        elif event['httpMethod'] == "GET" and event['path'] == "/scheduled":
            result = get_scheduled_task()
        elif event['httpMethod'] == "GET" and event['path'].startswith('/task'):
            result = get_task("task1")            
        else:
            result = {"Error": f"Invalid method or path - method: {event['httpMethod']}, path:{event['path']}"}          

        data = get_result(0, result)
        return {
            "statusCode":200,
            "body": json.dumps(data)
        }
    except Exception as e:
        logging.error(e)
        data = get_result(1, str(e))
        return {
            "statusCode":200,
            "body": json.dumps(data)
        }
       

def get_result(success, data):
        result = {}
        result['success'] = success
        if success == 0:
            result['result'] = data
        else:
            result['error'] = data      
        return result

def init():
    try:
        global secret_client
        global secret_token

        client = boto3.client(
            'secretsmanager', 
            region_name=region,
        )
        secret_response = client.get_secret_value(
                SecretId=secret_name_client
            )
        secret_client = json.loads(secret_response['SecretString'])
        secret_response = client.get_secret_value(
                SecretId=secret_name_token
            )
        secret_token = json.loads(secret_response['SecretString'])

    except Exception as e:
        raise e       

def get_agents():
    try:
        requestHeaders = {
            "Authorization": f"{ secret_token['token_type'] } { secret_token['access_token']}"
        }
        
        response = requests.get(agents_url, headers=requestHeaders)
        if response.status_code == 200:
            print("Got roles")
        else:
            print(f"Failure: { str(response.status_code) } - { response.reason }")
            raise Exception(f"Failure to get Genesys users: { str(response.status_code) } - { response.reason }")

        return response.json()   
    except Exception as e:
        raise e        

def get_skills():
    try:
        requestHeaders = {
            "Authorization": f"{ secret_token['token_type'] } { secret_token['access_token']}"
        }
        
        response = requests.get(skills_url, headers=requestHeaders)
        if response.status_code == 200:
            print("Got roles")
        else:
            print(f"Failure: { str(response.status_code) } - { response.reason }")
            raise Exception(f"Failure to get Genesys skills: { str(response.status_code) } - { response.reason }")

        return response.json()
    except Exception as e:
        raise e

def update_token():
    try:
        global secret_token
        keyId = secret_client['CLIENT_ID']
        sKeyId = secret_client['SECRET_KEY']
        access_token = get_token()
        
        expires_in = access_token['expires_in']
        expires_time = int(time.time()) + int(expires_in)
        access_token['expires_time'] = expires_time

        secret_token = access_token

        client = boto3.client(
            'secretsmanager', 
            region_name=region,
        )
        secret_response = client.put_secret_value(
                SecretId=secret_name_token,
                SecretString=json.dumps(secret_token)
            )
        return secret_response    

    except Exception as e:
        raise e

def get_token():
    try:
        GENESYS_CLIENT_ID = secret_client['GENESYS_CLIENT_ID']
        GENESYS_SECRET = secret_client['GENESYS_SECRET']

        # Base64 encode the client ID and client secret
        authorization = base64.b64encode(bytes(GENESYS_CLIENT_ID + ":" + GENESYS_SECRET, "ISO-8859-1")).decode("ascii")

        # Prepare for POST /oauth/token request
        request_headers = {
            "Authorization": f"Basic {authorization}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        request_body = {
            "grant_type": "client_credentials"
        }

        # Get token
        response = requests.post(token_url, data=request_body, headers=request_headers)
      
        # Check response
        if response.status_code == 200:
            print("Got token")
        else:
            print(f"Failure: { str(response.status_code) } - { response.reason }")
            raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")

        # Get JSON response body
        response_json = response.json()

        return  response_json      
    except Exception as e:
        raise e

def get_scheduled():
    try:
        dynamodb = boto3.resource(
            'dynamodb', 
            region_name=region,
        )
        table = dynamodb.Table('scheduled_task')
        response = response = table.query(
            KeyConditionExpression=Key('task').eq('task')
        )
        response_json = response
        print(response_json)

        return response_json   
    except Exception as e:
        raise e          

def get_task(task_name):
    try:
        dynamodb = boto3.resource(
            'dynamodb', 
            region_name=region,
        )
        table = dynamodb.Table('task_details')
        response = response = table.query(
            KeyConditionExpression=Key('task_name').eq('task1')
        )
        response_json = response
        print(response_json)

        return response_json   
    except Exception as e:
        raise e  