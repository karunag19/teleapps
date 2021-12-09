import base64, requests
import boto3
import json
import logging
import time
from boto3.dynamodb.conditions import Key
from jsonschema import validate, ValidationError

genesys_environment = "mypurecloud.com.au"
token_url = f"https://login.{genesys_environment}/oauth/token"
skills_url = f"https://api.{genesys_environment}/api/v2/routing/skills"
agents_url = f"https://api.{genesys_environment}/api/v2/users"
env = {
    "secret_client_key" : "karuna_secret_key",
    "secret_token_key" : "g_access_key",
    "genesys_environment" : "mypurecloud.com.au",
    "token_url" : token_url,
    "skills_url" : skills_url,
    "agents_url" : agents_url,
    "region" : "ap-southeast-2"
}

def lambda_handler(event, context):

    try:

        genesys = Lambda_Genesys(event, context, env)
        result = genesys.execute_method()
        return get_result(0, result)

    except Exception as e:
        logging.error(e)
        return get_result(1, str(e))

def get_result(success, data):
    result = {}
    result['success'] = success
    if success == 0:
        result['result'] = data
    else:
        result['error'] = data      
    final_result = {
        "statusCode":200,
        "body": json.dumps(result),
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
        }
    } 
    return final_result  

class Lambda_Genesys():
    

    def __init__(self, event, context, env):
        self.event = event
        self.context = context
        self.env = env

        try:
            client = boto3.client(
                'secretsmanager', 
                region_name = self.env['region'],
            )
            secret_response = client.get_secret_value(
                    SecretId = self.env["secret_client_key"]
                )
            self.secret_client = json.loads(secret_response['SecretString'])
            secret_response = client.get_secret_value(
                    SecretId=self.env["secret_token_key"]
                )
            self.secret_token = json.loads(secret_response['SecretString'])  

            token_ex_time = int(self.secret_token['expires_time'])
            if time.time() >  token_ex_time:
                self.__update_token()    

        except Exception as e:
            raise e 

    def execute_method(self):
        try:
            if isinstance(self.event, dict) and "path" in self.event:
                param = self.event.get('path','').split('/')
                print(param)
                if len(param) < 3:
                    raise Exception(f"Invalid method name")
                handler_name = f"{self.event.get('httpMethod','').lower()}_{param[2]}"
                print(handler_name)
                handler = getattr(self, handler_name, None)
                if handler:
                    if len(param) > 3:
                        result = handler(param = param[3])
                    else:
                        result = handler()
                else:
                    raise Exception(f"Invalid method type({self.event.get('httpMethod','')}) or name({param[2]})")
                return result
        except Exception as e:
            raise e

    def __update_token(self):
        try:
            keyId = self.secret_client['CLIENT_ID']
            sKeyId = self.secret_client['SECRET_KEY']
            access_token = self.__get_token()
            
            expires_in = access_token['expires_in']
            expires_time = int(time.time()) + int(expires_in)
            access_token['expires_time'] = expires_time

            self.secret_token = access_token

            client = boto3.client(
                'secretsmanager', 
                region_name=self.env["region"],
            )
            secret_response = client.put_secret_value(
                    SecretId=self.env['secret_token_key'],
                    SecretString=json.dumps(self.secret_token)
                )
            return secret_response    

        except Exception as e:
            raise e

    def __get_token(self):
        try:
            GENESYS_CLIENT_ID = self.secret_client['GENESYS_CLIENT_ID']
            GENESYS_SECRET = self.secret_client['GENESYS_SECRET']

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
            response = requests.post(self.env["token_url"], data=request_body, headers=request_headers)
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

    def get_agents(self):
        try:
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            
            response = requests.get(self.env["agents_url"], headers=requestHeaders)
            if response.status_code == 200:
                print("Got roles")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys users: { str(response.status_code) } - { response.reason }")

            return response.json()   
        except Exception as e:
            raise e 

    def get_skills(self):
        try:
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            
            response = requests.get(self.env["skills_url"], headers=requestHeaders)
            if response.status_code == 200:
                print("Got roles")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys skills: { str(response.status_code) } - { response.reason }")

            return response.json()
        except Exception as e:
            raise e

    def get_scheduled(self, param=None):
        try:
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('scheduled_task')
            if param == None:
                response = response = table.query(
                    KeyConditionExpression=Key('task').eq('task') 
                )
            else:
                response = response = table.query(
                    KeyConditionExpression=Key('task').eq('task') & Key('name').eq(param)
                )
            response_json = response['Items']
            return response_json   
        except Exception as e:
            raise e 

    def post_scheduled(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("scheduled", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('scheduled_task')
            response = response = table.query(
                KeyConditionExpression=Key('task').eq('task') 
            )
            response_json = response['Items']
            return response_json   
        except Exception as e:
            raise e 

    def get_task(self, param=None):
        try:
            if param == None:
                raise Exception(f"Missing task name in the path(/genesys/task/<task name>")

            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('task_details')
            response = response = table.query(
                KeyConditionExpression=Key('task_name').eq(param)
            )
            response_json = response
            return response_json   
        except Exception as e:
            raise e 

    def __validate_schema(self, schema, body_json):
        try:
            if schema == "scheduled":
                scheduled = {
                    "type" : "object",
                    "properties" : {
                        "name" : {"type" : "string"},
                        "repet_on" : {"type" : "array", "items" : {"type" : "string","enum" : ["0","1"]}, "minItems": 7},
                        "repet_type" : {"type" : "string", "enum" : ["D", "W", "M", "Y"]},
                        "start_dt" : {"type" : "string"},
                        "run_time" : {"type" : "string"},
                    },
                    "required": [ "name", "repet_on", "repet_type", "start_dt", "run_time"]
                }
                validate(instance=body_json, schema=scheduled)
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 
    
