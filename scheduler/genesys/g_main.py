import os
import base64, requests
import boto3
import json
import logging
import time
from datetime import datetime
from datetime import date
from dateutil.relativedelta import relativedelta
from dateutil import tz, parser
from boto3.dynamodb.conditions import Key, Attr
from jsonschema import validate, ValidationError, Draft7Validator, validators
from decimal import Decimal

from concurrent.futures import ThreadPoolExecutor

genesys_environment = os.getenv('GENESYS_ENV', "mypurecloud.com.au") 
region = os.getenv('REGION', "ap-southeast-2") 
secret_client = os.getenv('SECRET_CLIENT', "karuna_secret_key") 
secret_token = os.getenv('SECRET_TOKEN', "g_access_key") 

token_url = f"https://login.{genesys_environment}/oauth/token"
skills_url = f"https://api.{genesys_environment}/api/v2/routing/skills?pageSize=500"
agents_url = f"https://api.{genesys_environment}/api/v2/users?pageSize=500"
# routing_url = f"https://api.{genesys_environment}/api/v2/users/AGENT_ID/routingskills" 
routing_url = f"https://api.{genesys_environment}/api/v2/users/AGENT_ID/routingskills/bulk" 
env = {
    "secret_client_key" : secret_client,
    "secret_token_key" : secret_token,
    "genesys_environment" : genesys_environment,
    "token_url" : token_url,
    "skills_url" : skills_url,
    "agents_url" : agents_url,
    "routing_url" : routing_url,
    "region" : region
}

def lambda_handler(event, context):

    try:

        genesys = Lambda_Genesys(event, context, env)
        result = genesys.execute_method()
        return get_result(1, result)

    except Exception as e:
        logging.error(e)
        return get_result(0, str(e))

def get_result(success, data):
    result = {}
    result['success'] = success
    if success == 1:
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
            print(f"EVENT: {self.event}")
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
            elif "detail-type" in self.event and self.event.get('detail-type') == "Scheduled Event":
                self.get_process_scheduled()

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
            print("__get_token")
            GENESYS_CLIENT_ID = self.secret_client['GENESYS_CLIENT_ID']
            GENESYS_SECRET = self.secret_client['GENESYS_SECRET']
            # GENESYS_CLIENT_ID = 'd684b8b1-2ac2-4476-b8a7-60a2eb498a45'
            # GENESYS_SECRET = 'BCD0_yFifgUyzuQ5Nq64wxzF-R6qSXajr8bWw59Lz8M'           


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
            print(f"response: {response}")
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
            table = dynamodb.Table('Genesys_scheduled')
            if param == None:
                response = response = table.query(
                    KeyConditionExpression=Key('p_key').eq('scheduled') 
                )
            else:
                response = response = table.query(
                    KeyConditionExpression=Key('p_key').eq('scheduled') & Key('scheduled_name').eq(param)
                )
            response_json = response['Items']
            # response_json = response
            for item in response_json:
                item['last_runtime'] = str(item['last_runtime']) 
                item['next_runtime'] = str(item['next_runtime'])
            return response_json   
        except Exception as e:
            raise e 

    def post_scheduled(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("scheduled", body_json, extn=True)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_scheduled')
            response = table.get_item(
                Key={
                    'p_key': 'scheduled',
                    'scheduled_name': body_json['scheduled_name']
                }
            )
            if "Item" in response:
                raise Exception(f"assignment with the same name: {body_json['scheduled_name']} is already available")
            
            next_runtime = self.__calc_nextruntime_UTC(body_json)
            epoch_next_runtime = int(next_runtime.timestamp())
            body_json['p_key'] = "scheduled"
            body_json['next_runtime'] = epoch_next_runtime
            body_json['last_runtime'] = 0
            response = table.put_item(
                Item=body_json
            )
            # start_time = body_json['start_time']
            # start_time_split = start_time.split(":")
            # self.__set_cron_job(body_json['scheduled_name'], start_time_split[0], start_time_split[1] )
            response_json = response
            return response_json   

            return body_json
        except Exception as e:
            raise e 

    def put_scheduled(self, param=None):
        try:
            if param == None:
                raise Exception(f"Missing assignment name in the path(/genesys/scheduled/<scheduled name>")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("put_scheduled", body_json, extn=True)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_scheduled')
            response = table.get_item(
                Key={
                    'p_key': 'scheduled',
                    'scheduled_name': param
                }
            )
            if not "Item" in response:
                raise Exception(f"No scheduled with the name: {param} is available")
            
            next_runtime = self.__calc_nextruntime_UTC(body_json)
            epoch_next_runtime = int(next_runtime.timestamp())
            body_json['p_key'] = "scheduled"
            body_json['scheduled_name'] = param
            body_json['next_runtime'] = epoch_next_runtime
            body_json['last_runtime'] = 0
            response = table.put_item(
                Item=body_json
            )
            # start_time = body_json['start_time']
            # start_time_split = start_time.split(":")
            # self.__set_cron_job(body_json['scheduled_name'], start_time_split[0], start_time_split[1] )
            response_json = response
            return response_json   

            return body_json
        except Exception as e:
            raise e 

    def delete_scheduled(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("del_scheduled", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_scheduled')
            response = table.delete_item(
                Key={
                    'p_key': 'scheduled',
                    'scheduled_name': body_json['scheduled_name']
                },
                ReturnValues="ALL_OLD"
            )
            response_json = response.get('Attributes', None) 
            if response_json != None:
                response['Attributes']['last_runtime'] = str(response_json['last_runtime']) 
                response['Attributes']['next_runtime'] = str(response_json['next_runtime'])            
            return response
        except Exception as e:
            raise e 

    def get_assignment(self, param=None):
        try:
            # if param == None:
            #     raise Exception(f"Missing assignment name in the path(/genesys/assignment/<schedule name>")

            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            
            if param == None:
                response = response = table.scan()
            else:    
                response = response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(param)
                )
            response_json = response
            return response_json   
        except Exception as e:
            raise e 

    def post_assignment(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("assignment", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.get_item(
                Key={
                    'assignment_name': body_json['assignment_name'],
                    'agent_name': body_json['agent_name']
                }
            )
            if "Item" in response:
                raise Exception(f"assignment with the same name: {body_json['assignment_name']} with agent_name: {body_json['agent_name']}  is already available")
            response = table.put_item(
                Item=body_json
            )
            response_json = response
            return response_json   
        except Exception as e:
            raise e 

    def post_assignment_bulk(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("assignment_bulk", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(body_json['assignment_name'])
            )
            print(f"RESPONSE: {response}")            
            if response['Count'] > 0:
                raise Exception(f"assignment with the same name: {body_json['assignment_name']} is already available")

            with table.batch_writer() as batch:
                for item in body_json['assignment']:
                    item['assignment_name'] = body_json['assignment_name']
                    batch.put_item(
                        Item=item
                    )
            response_json = {"message":"bulk assignment success"} 
            return response_json   
        except Exception as e:
            raise e

    def put_assignment(self, param=None):
        try:

            if param == None:
                raise Exception(f"Missing assignment name in the path(/genesys/assignment/<assignment name>")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("put_assignment", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.get_item(
                Key={
                    'assignment_name': param,
                    'agent_name': body_json['agent_name']
                }
            )
            if not "Item" in response:
                raise Exception(f"No assignment with the name: {param} and agent: {body_json['agent_name']} ")

            response = table.update_item(
                Key={
                    'assignment_name': param,
                    'agent_name': body_json['agent_name']
                },
                UpdateExpression="SET #skills=:s_prof",
                ExpressionAttributeNames={
                    "#skills": "skills"
                    },
                ExpressionAttributeValues={
                    ':s_prof': body_json["skills"],
                }
            ) 

            return response  
        except Exception as e:
            raise e 

    def delete_assignment(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("del_assignment", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.delete_item(
                Key={
                    'assignment_name': body_json['assignment_name'],
                    'agent_name': body_json['agent_name']
                },
                ReturnValues="ALL_OLD"
            )
            response_json = response
            return response_json   
        except Exception as e:
            raise e
    
    def delete_all_assignment(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("del_all_assignment", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = response = table.query(
                KeyConditionExpression=Key('assignment_name').eq(body_json['assignment_name'])
            )
            if response["Count"] == 0:
                raise Exception(f"Invalid assignment_name: {body_json['assignment_name']}")           
            with table.batch_writer() as batch:
                for item in response['Items']:
                    assignment_name = body_json['assignment_name']
                    agent_name = item['agent_name']
                    batch.delete_item( 
                        Key={
                            'assignment_name': assignment_name,
                            'agent_name': agent_name
                        }
                    )
            response_json = {"message":f"delete assignment({assignment_name}) success"} 
            return response_json   
        except Exception as e:
            raise e
    def get_skill(self, param=None):
        try:
            if param == None:
                raise Exception(f"Missing assignment name in the path(/genesys/skill/<schedule name>")

            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment_skill')
            response = response = table.query(
                KeyConditionExpression=Key('assignment_name').eq(param)
            )
            response_json = response
            return response_json   
        except Exception as e:
            raise e 

    def post_skill(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("assignment_skill", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment_skill')
            response = table.get_item(
                Key={
                    'assignment_name': body_json['assignment_name'],
                    'skill_name': body_json['skill_name']
                }
            )
            if "Item" in response:
                raise Exception(f"assignment with the same name: {body_json['assignment_name']} with skill_name: {body_json['skill_name']}  is already available")
            response = table.put_item(
                Item=body_json
            )
            response_json = response
            return response_json   
        except Exception as e:
            raise e 

    def delete_skill(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("del_assignment_skill", body_json)
            print(body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment_skill')
            response = table.delete_item(
                Key={
                    'assignment_name': body_json['assignment_name'],
                    'skill_name': body_json['skill_name']
                },
                ReturnValues="ALL_OLD"
            )
            response_json = response
            return response_json   
        except Exception as e:
            raise e

    def __validate_schema(self, schema, body_json, extn = False):
        try:
            if schema == "scheduled":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "scheduled_name" : {"type" : "string"},
                        "assignment_name" : {"type" : "string"},
                        "repeat_on" : {"type" : "array", "items" : {"type" : "string","enum" : ["0","1"]}, "minItems": 7},
                        "repeat_type" : {"type" : "string", "enum" : ["D", "W", "M", "Y"]},
                        "date_utc" : {"type" : "string", "description": "Format - 2022-01-04T05:30:00.000Z"},
                        "start_dt" : {"type" : "ex_date", "description": "Format - YYYY-MM-DD"},
                        "start_time" : {"type" : "ex_time", "description": "Format - HH:MM"},
                    },
                    "required": [ "scheduled_name","assignment_name", "repeat_on", "repeat_type", "date_utc"]
                }
            elif schema == "put_scheduled":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "repeat_on" : {"type" : "array", "items" : {"type" : "string","enum" : ["0","1"]}, "minItems": 7},
                        "repeat_type" : {"type" : "string", "enum" : ["D", "W", "M", "Y"]},
                        "date_utc" : {"type" : "string", "description": "Format - 2022-01-04T05:30:00.000Z"},
                        "start_dt" : {"type" : "ex_date", "description": "Format - YYYY-MM-DD"},
                        "start_time" : {"type" : "ex_time", "description": "Format - HH:MM"},
                    },
                    "required": [ "assignment_name", "repeat_on", "repeat_type", "date_utc"]
                }                
            elif schema == "del_scheduled":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "scheduled_name" : {"type" : "string"},
                    },
                    "required": [ "scheduled_name"]
                }                
            elif schema == "assignment":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "agent_name" : {"type" : "string"},
                        "agent_id" : {"type" : "string"},
                        "skills" : {
                            "type" : "array", 
                            "items" : {
                                "type" : "object",
                                "properties": {
                                    "skill_name" :  {"type" : "string"},
                                    "skill_id" :  {"type" : "string"},
                                    "proficiency" :  {"type" : "string"}
                                },
                                "required": [ "skill_name", "skill_id", "proficiency"]
                            },
                            "minItems": 1
                        }
                    },
                    "required": [ "assignment_name", "agent_name", "agent_id", "skills"]
                }    
            elif schema == "put_assignment":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "agent_name" : {"type" : "string"},
                        "skills" : {
                            "type" : "array", 
                            "items" : {
                                "type" : "object",
                                "properties": {
                                    "skill_name" :  {"type" : "string"},
                                    "skill_id" :  {"type" : "string"},
                                    "proficiency" :  {"type" : "string"}
                                },
                                "required": [ "skill_name", "skill_id", "proficiency"]
                            },
                            "minItems": 1
                        }
                    },
                    "required": [ "agent_name", "skills"]
                }                   
            elif schema == "assignment_bulk":
                schema_obj = {
                    "type" : "object",
                    "properties" : {     
                        "assignment_name" : {"type" : "string"},               
                        "assignment": {
                            "type": "array",
                            "items": {
                                "type" : "object",
                                "properties" : {
                                    "agent_name" : {"type" : "string"},
                                    "agent_id" : {"type" : "string"},
                                    "skills" : {
                                        "type" : "array", 
                                        "items" : {
                                            "type" : "object",
                                            "properties": {
                                                "skill_name" :  {"type" : "string"},
                                                "skill_id" :  {"type" : "string"},
                                                "proficiency" :  {"type" : "string"}
                                            },
                                            "required": [ "skill_name", "skill_id", "proficiency"]
                                        },
                                        "minItems": 1
                                    }
                                },
                                "required": ["agent_name", "agent_id", "skills"]
                            },
                            "minItems": 1
                        }
                    },
                    "required": ["assignment_name", "assignment"]
                }   
            elif schema == "mass_update":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "skill_id" :  {"type" : "string"},
                        "proficiency" :  {"type" : "string"}
                    },
                    "required": [ "assignment_name", "skill_id", "proficiency"]
                }    
            elif schema == "assignment_add_skill":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "skill_name" :  {"type" : "string"},
                        "skill_id" :  {"type" : "string"},
                        "proficiency" :  {"type" : "string"}
                    },
                    "required": [ "assignment_name", "skill_id", "proficiency"]
                }                                                    
            elif schema == "del_assignment":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "agent_name" : {"type" : "string"}
                    },
                    "required": [ "assignment_name", "agent_name"]
                } 
            elif schema == "del_all_assignment":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                    },
                    "required": [ "assignment_name"]
                }                  
            elif schema == "assignment_skill":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "skill_name" : {"type" : "string"},
                        "skill_id" : {"type" : "string"}      
                    },
                    "required": [ "assignment_name", "skill_name", "skill_id"]
                }     
            elif schema == "del_assignment_skill":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "skill_name" : {"type" : "string"}
                    },
                    "required": [ "assignment_name", "skill_name"]
                }
            elif schema == "clone":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "assignment_name" : {"type" : "string"},
                        "clone_name" : {"type" : "string"}
                    },
                    "required": [ "assignment_name", "clone_name"]
                }                                                                                
            if extn:
                self.__extn_validate(instance=body_json, schema=schema_obj)
            else:
                validate(instance=body_json, schema=schema_obj)
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 
    
    def __extn_validate(self, instance=None, schema=None ):
        BaseVal = Draft7Validator
        # Build a new type checker
        def is_date(checker, inst):
            try:
                datetime.strptime(inst, '%Y-%m-%d')
                return True
            except ValueError:
                return False
        def is_time(checker, inst):
            try:
                datetime.strptime(inst, '%H:%M')
                return True
            except ValueError:
                return False
        def is_datetime(checker, inst):
            try:
                # datetime.strptime(inst, '%Y-%m-%d-%H.%M.%S.%f')
                datetime.strptime(inst, '%Y-%m-%d-%H.%M.%S')
                return True
            except ValueError:
                return False

        #   date_check = BaseVal.TYPE_CHECKER.redefine(u'orderdatetime_1', is_datetime)
        checker_type = {
            'ex_time': is_time,
            'ex_date': is_date,
            'ex_datetime': is_datetime,
        }
        date_check = BaseVal.TYPE_CHECKER.redefine_many(checker_type)
        # Build a validator with the new type checker
        Validator = validators.extend(BaseVal, type_checker=date_check)
        # Run the new Validator
        Validator(schema=schema).validate(instance)

    # def __calc_nextruntime(self, param):
    #     try:
    #         dt_start_datetime = datetime.strptime(f"{param['start_dt']}-{param['start_time']}", '%Y-%m-%d-%H:%M')
    #         dt_start_date = datetime.strptime(f"{param['start_dt']}", '%Y-%m-%d')
    #         dt_today_date = datetime.strptime(f"{date.today()}", '%Y-%m-%d')

    #         print(f"dt_start_date: {dt_start_date}")
    #         print(f"dt_today_date: {dt_today_date}")
    #         if dt_start_date > dt_today_date:
    #             delta_day = 0
    #             dt_schedule = datetime.strptime(f"{param['start_dt']}-{param['start_time']}", '%Y-%m-%d-%H:%M')
    #         else:
    #             delta_day = 1
    #             dt_schedule = datetime.strptime(f"{dt_today_date.year}-{dt_today_date.month}-{dt_today_date.day}-{param['start_time']}", '%Y-%m-%d-%H:%M')
    #             if param['repeat_type'] == "M":
    #                 dt_schedule = datetime.strptime(f"{dt_today_date.year}-{dt_today_date.month}-{dt_start_date.day}-{param['start_time']}", '%Y-%m-%d-%H:%M')
    #             if param['repeat_type'] == "Y":
    #                 dt_schedule = datetime.strptime(f"{dt_today_date.year}-{dt_start_date.month}-{dt_start_date.day}-{param['start_time']}", '%Y-%m-%d-%H:%M')
    #             if dt_schedule > datetime.now():
    #                 delta_day = 0

    #         print(f"dt_now: {datetime.now()}")
    #         print(f"dt_schedule: {dt_schedule}")
    #         print(f"delta_day: {delta_day}")
    #         if param['repeat_type'] == "D":
    #             dt_schedule = dt_schedule + relativedelta(days=delta_day)
    #             print(f"NEXT RUN TIME: {dt_schedule}")
    #             return dt_schedule
    #         elif param['repeat_type'] == "W":
    #             #  week 0 to 6 -> 0-Monday, 6 - Sunday
    #             print(f"dt_schedule.timetuple: {dt_schedule.timetuple()}")
    #             time_tuple = dt_schedule.timetuple()
    #             dt_today_day = time_tuple[6]
    #             dt_next_day = dt_today_day + delta_day
    #             if dt_next_day == 7:
    #                 dt_next_day = 0
    #             for i in range(0,7):
    #                 if param['repeat_on'][dt_next_day] == "1":
    #                     dt_schedule = dt_schedule + relativedelta(days=+ delta_day)
    #                     print(f"NEXT RUN TIME: {dt_schedule}")
    #                     return dt_schedule
    #                 else:
    #                     dt_next_day = dt_next_day + 1
    #                     if dt_next_day > 6:
    #                         dt_next_day = 0
    #                 delta_day = delta_day + 1
    #         elif param['repeat_type'] == "M":
    #             dt_schedule_temp = datetime.strptime(f"{dt_schedule.year}-{dt_schedule.month}-{dt_start_datetime.day}-{param['start_time']}", '%Y-%m-%d-%H:%M')
    #             dt_schedule = dt_schedule_temp + relativedelta(months=+delta_day)
    #             print(f"NEXT RUN TIME: {dt_schedule}")
    #             return dt_schedule
    #         elif param['repeat_type'] == "Y":
    #             dt_schedule_temp = datetime.strptime(f"{dt_schedule.year}-{dt_start_datetime.month}-{dt_start_datetime.day}-{param['start_time']}", '%Y-%m-%d-%H:%M')        
    #             dt_schedule = dt_schedule + relativedelta(years=+delta_day)
    #             print(f"NEXT RUN TIME: {dt_schedule}")            
    #             return dt_schedule
    #         else:
    #             return dt_start_datetime
    #     except Exception as e:
    #         raise e 

    def __calc_nextruntime_UTC(self, param):
        try:
            utc_time = parser.parse("2022-01-15T11:30:00.000Z")
            dt_year = utc_time.year
            dt_month = utc_time.month
            dt_day = utc_time.day
            dt_hours = utc_time.hour
            dt_minutes = utc_time.minute 

            p_utc_time = param['date_utc']
            utc_time = parser.parse(p_utc_time)
            p_start_dt = f"{utc_time.year}-{utc_time.month}-{utc_time.day}"
            p_start_time = f"{utc_time.hour}:{utc_time.minute}" 
            dt_start_datetime = datetime.strptime(f"{p_start_dt}-{p_start_time}", '%Y-%m-%d-%H:%M')
            dt_start_date = datetime.strptime(f"{p_start_dt}", '%Y-%m-%d')
            dt_today_date = datetime.strptime(f"{date.today()}", '%Y-%m-%d')

            print(f"dt_start_date: {dt_start_date}")
            print(f"dt_today_date: {dt_today_date}")
            if dt_start_date > dt_today_date:
                delta_day = 0
                dt_schedule = datetime.strptime(f"{p_start_dt}-{p_start_time}", '%Y-%m-%d-%H:%M')
            else:
                delta_day = 1
                dt_schedule = datetime.strptime(f"{dt_today_date.year}-{dt_today_date.month}-{dt_today_date.day}-{p_start_time}", '%Y-%m-%d-%H:%M')
                if param['repeat_type'] == "M":
                    dt_schedule = datetime.strptime(f"{dt_today_date.year}-{dt_today_date.month}-{dt_start_date.day}-{p_start_time}", '%Y-%m-%d-%H:%M')
                if param['repeat_type'] == "Y":
                    dt_schedule = datetime.strptime(f"{dt_today_date.year}-{dt_start_date.month}-{dt_start_date.day}-{p_start_time}", '%Y-%m-%d-%H:%M')
                if dt_schedule > datetime.now():
                    delta_day = 0

            print(f"dt_now: {datetime.now()}")
            print(f"dt_schedule: {dt_schedule}")
            print(f"delta_day: {delta_day}")
            if param['repeat_type'] == "D":
                dt_schedule = dt_schedule + relativedelta(days=delta_day)
                print(f"NEXT RUN TIME: {dt_schedule}")
                return dt_schedule
            elif param['repeat_type'] == "W":
                #  week 0 to 6 -> 0-Monday, 6 - Sunday
                print(f"dt_schedule.timetuple: {dt_schedule.timetuple()}")
                time_tuple = dt_schedule.timetuple()
                dt_today_day = time_tuple[6]
                dt_next_day = dt_today_day + delta_day
                if dt_next_day == 7:
                    dt_next_day = 0
                for i in range(0,7):
                    if param['repeat_on'][dt_next_day] == "1":
                        dt_schedule = dt_schedule + relativedelta(days=+ delta_day)
                        print(f"NEXT RUN TIME: {dt_schedule}")
                        return dt_schedule
                    else:
                        dt_next_day = dt_next_day + 1
                        if dt_next_day > 6:
                            dt_next_day = 0
                    delta_day = delta_day + 1
            elif param['repeat_type'] == "M":
                dt_schedule_temp = datetime.strptime(f"{dt_schedule.year}-{dt_schedule.month}-{dt_start_datetime.day}-{p_start_time}", '%Y-%m-%d-%H:%M')
                dt_schedule = dt_schedule_temp + relativedelta(months=+delta_day)
                print(f"NEXT RUN TIME: {dt_schedule}")
                return dt_schedule
            elif param['repeat_type'] == "Y":
                dt_schedule_temp = datetime.strptime(f"{dt_schedule.year}-{dt_start_datetime.month}-{dt_start_datetime.day}-{p_start_time}", '%Y-%m-%d-%H:%M')        
                dt_schedule = dt_schedule + relativedelta(years=+delta_day)
                print(f"NEXT RUN TIME: {dt_schedule}")            
                return dt_schedule
            else:
                return dt_start_datetime
        except Exception as e:
            raise e 

    def get_process_scheduled(self):
        try:
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_scheduled')
            epoch_current = int(time.time())
            response = table.scan(
                FilterExpression=Attr('next_runtime').lt(epoch_current)
            )
            if response["Count"] == 0:
                print("NO EVENT SCHEDULED")
                return {"success": 1}

            response_json = response['Items']
            for item in response_json:
                self.get_run_now(item['assignment_name'])
                self.__update_scheduled(item)
                item['last_runtime'] = str(item['last_runtime']) 
                item['next_runtime'] = str(item['next_runtime'])
            return response_json

        except Exception as e:
            raise e 

    def get_run_now(self, param):
        try:
            print("AFTER - get_process_assignment")    
            assignment_name = param
            # assignment_name = "assignment_3"
            print(f"scheduled_name: {assignment_name}")
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = response = table.query(
                KeyConditionExpression=Key('assignment_name').eq(assignment_name) 
            )    
            response_json = response['Items']

            map_assignment =[]
            for item in response_json:
                map_assignment.append(item)
            print(f"LENGTH: {len(map_assignment)}")
            with ThreadPoolExecutor(max_workers = 10) as executor:
                task = executor.map(self.__asign_skills, map_assignment)
            return response_json

        except Exception as e:
            raise e             

    def post_clone(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("clone", body_json) 
            print("AFTER __validate_schema")           
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(body_json['clone_name'])
            )            
            if response['Count'] > 0:
                raise Exception(f"assignment with the same name: {body_json['clone_name']} is already available")
                        
            response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(body_json['assignment_name'])
            )
            print(f"AFTER query - response {response}") 
            if "Items" in response:
                print(f"AFTER if ITEMS - Items: {response['Items']}") 
                with table.batch_writer() as batch:
                    for item in response['Items']:
                        item['assignment_name'] = body_json['clone_name']
                        batch.put_item(
                            Item=item
                        )
                    print(f"AFTER able.batch_writer()")
            
            print(f"AFTER if end")
            response_json = {"message":"clone assignment success"}  
            return response_json         
        except Exception as e:
            raise e 

    def put_mass_update(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("mass_update", body_json) 
            print("AFTER __validate_schema")           
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(body_json["assignment_name"])
            )            
            if response['Count'] == 0:
                raise Exception(f"Invalid assignment ({body_json['assignment_name']}) or no user assigned for this assignment")

            with table.batch_writer() as batch:
                for item in response["Items"]:
                    count = 0
                    for skill in item["skills"]:
                        if skill["skill_id"] == body_json["skill_id"]:
                            item["skills"][count]["proficiency"] = body_json["proficiency"]
                        count = count + 1
                    batch.put_item(
                        Item=item
                    )
            response_json = {"message": "mass update success"}
            return response_json         
        except Exception as e:
            raise e 

    def post_assignment_skill(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("assignment_add_skill", body_json) 
            print("AFTER __validate_schema")           
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(body_json["assignment_name"])
            )            
            if response['Count'] == 0:
                raise Exception(f"Invalid assignment ({body_json['assignment_name']}) or no user assigned for this assignment")

            with table.batch_writer() as batch:
                for item in response["Items"]:
                    new_skill = {}
                    new_skill['skill_id'] = body_json["skill_id"]
                    new_skill['skill_name'] = body_json["skill_name"]
                    new_skill['proficiency'] = body_json["proficiency"]
                    item["skills"].append(new_skill) 
                    batch.put_item(
                        Item=item
                    )
            response_json = {"message": "add assignment skill - success"}
            return response_json         
        except Exception as e:
            raise e 

    def delete_assignment_skill(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("mass_update", body_json) 
            print("AFTER __validate_schema")           
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table('Genesys_assignment')
            response = table.query(
                    KeyConditionExpression=Key('assignment_name').eq(body_json["assignment_name"])
            )            
            if response['Count'] == 0:
                raise Exception(f"Invalid assignment ({body_json['assignment_name']}) or no user assigned for this assignment")

            with table.batch_writer() as batch:
                for item in response["Items"]:
                    new_skills = []
                    for skill in item["skills"]:
                        if skill["skill_id"] != body_json["skill_id"]:
                            new_skills.append(skill)
                    item["skills"] = new_skills
                    batch.put_item(
                        Item=item
                    )
            response_json = {"message": "delete assignment skill - success"}
            return response_json         
        except Exception as e:
            raise e 

    def __asign_skills(self, item_json):
        try:
            print("AFTER - __asign_skills")          
            print(item_json)
            print(f"agent_id: {item_json['agent_id']}")
            print(f"agent_name: {item_json['agent_name']}")
            agent_id = item_json['agent_id']

            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}",
                "Content-Type": "application/json",
            }

            skill_add_list = []
            # skill_remove_list = []
            for skill in item_json['skills']:
                body = {
                        "id": skill['skill_id'],
                        "proficiency": skill['proficiency']
                    }
                # if int(skill['proficiency']) > 0:
                skill_add_list.append(body)
                # else:
                #     skill_remove_list.append(body)
            
            print(f"skill_add_list: {skill_add_list}")
            routing_url_temp = self.env["routing_url"]
            routing_url = routing_url_temp.replace("AGENT_ID", agent_id)                    
            request_body = json.dumps(skill_add_list)
            # PATCH /api/v2/users/{userId}/routingskills/bulk -> Bulk add routing skills to user
            # PUT /api/v2/users/{userId}/routingskills/bulk -> Replace all routing skills assigned to a user
            response = requests.put(routing_url, data=request_body, headers=requestHeaders)
            if response.status_code == 200:
                print("Genesys - Skills updated")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure routing: { str(response.status_code) } - { response.reason }")

            # if len(skill_remove_list) > 0:
            #     # if we are planning to use PATCH, then we have to delete the users with prociency 0.
            #     # DELETE /api/v2/users/{userId}/routingskills/{skillId} -> Remove routing skill from user
            #     pass

        except Exception as e:
            raise e                

    def __update_scheduled(self, item_json):
        try:
            next_runtime = self.__calc_nextruntime_UTC(item_json)
            epoch_next_runtime = int(next_runtime.timestamp())
            print(f"NEXT RUNTIME: {next_runtime}")
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )            
            table = dynamodb.Table('Genesys_scheduled')
            response = table.update_item(
                Key={
                    'p_key': 'scheduled',
                    'scheduled_name': item_json['scheduled_name']
                },
                UpdateExpression="SET last_runtime=:l_run, next_runtime=:n_run",
                ExpressionAttributeValues={
                    ':n_run': Decimal(epoch_next_runtime),
                    ':l_run': Decimal(item_json['next_runtime'])
                }
            )
        except Exception as e:
            raise e             

    def __set_cron_job(self, scheduled_name, hrs, min=0):
        try:
            client = boto3.client(
                'events',
                region_name = self.env['region'],
                aws_access_key_id = self.secret_client['CLIENT_ID'],
                aws_secret_access_key= self.secret_client['SECRET_KEY']              
            )
            rule = client.put_rule(
                Name = scheduled_name,
                # ScheduleExpress\ion="rate(2 minutes)",
                ScheduleExpression = f"cron({int(min)} {int(hrs)} * * ? *)",
                State="ENABLED",
                RoleArn="arn:aws:iam::070618480609:role/TeleApps-Schedule"
            )
            client.put_targets(
                Rule = scheduled_name,
                Targets=[
                    {
                        "Id": "TeleApps_Genesys",
                        "Arn": "arn:aws:lambda:ap-southeast-2:070618480609:function:Genesys",
                        "Input": json.dumps({"scheduled_name": scheduled_name})
                    }
                ]
            )
            return {"message":"put_target success"}
        except Exception as e:
            raise e                

    def __del_cron_job(self, scheduled_name):
        try:
            client = boto3.client(
                'events',
                region_name = self.env['region'],
                aws_access_key_id = self.secret_client['CLIENT_ID'],
                aws_secret_access_key= self.secret_client['SECRET_KEY']
            )
            response = client.remove_targets(
                Rule=scheduled_name,
                Ids=[
                    'TeleApps_Genesys'
                ],
                Force=True
            )
            rule = client.delete_rule(
                Name = scheduled_name,
                Force= True
            )
            return {"message":"remove scheduled success"}
        except Exception as e:
            raise e 

    def get_test(self):
        try:
            # dt_time = datetime.now()
            # to_zone = tz.gettz('Asia/Kolkata')
            # to_dt = datetime.now(tz=to_zone)
            # dt_utc = parser.parse("2022-01-15T11:30:00.000Z")
            # dt_year = dt_utc.year
            # dt_month = dt_utc.month
            # dt_day = dt_utc.day
            # dt_hours = dt_utc.hour
            # dt_minutes = dt_utc.minute   

            # param =    {
            #     "p_key": "scheduled",
            #     "scheduled_name": "TeleappsTest",
            #     "date_utc": "2022-01-05T11:30:00.000Z",
            #     "assignment_name": "Demo2",
            #     "repeat_type": "D",
            #     "repeat_on": [
            #     "0",
            #     "0",
            #     "0",
            #     "0",
            #     "0",
            #     "0",
            #     "0"
            #     ],
            #     "start_time": "17:00",
            #     "last_runtime": 0,
            #     "next_runtime": 1642266000,
            #     "start_dt": "2022-01-15"
            #     }
            # next_runtime = self.__calc_nextruntime_UTC(param)             
            # Karuna - working
            # response = table.update_item(
            #     Key={
            #         'assignment_name': "assignment_3",
            #         'agent_name': "Karuna"
            #     },
            #     UpdateExpression="SET #skills.DMSkill1.proficiency=:s_prof",
            #     ExpressionAttributeNames={
            #         "#skills": "skills"
            #         },
            #     ExpressionAttributeValues={
            #         ':s_prof': "1",
            #     }
            # ) 
            import os           
            return {
                "Message": os.getenv('GENESYS_ENV', "default_value"), 
                "Message_g": os.getenv('REGION', "default_value_g"), 
                }
        except Exception as e:
            raise e                