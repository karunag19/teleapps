import boto3
import json
import logging
import os
import random

from jsonschema import validate, ValidationError
from boto3.dynamodb.conditions import Key

region = os.getenv('REGION', "ap-southeast-2") 
tbl_api_key = os.getenv('TBL_API_KEY', "demo_api_key") 

env = {
    "region" : region,
    "tbl_api_key" : tbl_api_key,
    "key_len": 128,
    "tbl_q_contacts": tbl_q_contacts,
    "tbl_contact_details": tbl_contact_details
}

def lambda_handler(event, context):
    try: 

        genesys = Lambda_KEY(event, context, env)
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

class Lambda_KEY():

    def __init__(self, event, context, env):
        self.event = event
        self.context = context
        self.env = env

        try:
            self.dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
        except Exception as e:
            raise e 

    def execute_method(self):
        try:
            if isinstance(self.event, dict) and "path" in self.event:
                param = self.event.get('path','').split('/')
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

    def get_tokens(self, param=None): 
        try:
            table = self.dynamodb.Table(self.env['tbl_api_key'])
            response = response = table.query(
                KeyConditionExpression=Key('p_key').eq('app_key') 
            )
            response_json = response['Items']
            return response_json   
        except Exception as e:
            raise e 

    def post_token(self):
        try:
            table = self.dynamodb.Table(self.env['tbl_api_key'])
            while True:
                token = self.__generate_key()
                print(f"TOKEN: {token}")
                response = table.get_item(
                    Key={
                        'p_key': 'app_key',
                        'token': token
                    }
                )
                if "Item" not in response:
                    break
            body_json = {}
            body_json['p_key'] = "app_key"
            body_json['token'] = token
            print(f"BEFORE INS")
            response = table.put_item(
                Item=body_json
            )
            response_json = response
            return body_json   
        except Exception as e:
            raise e 

    def delete_token(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("del_key", body_json)
            dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            )
            table = dynamodb.Table(self.env['tbl_api_key'])
            response = table.get_item(
                Key={
                    'p_key': 'app_key',
                    'token': body_json['token']
                }
            )
            if "Item" not in response:
                raise Exception(f"Invalid key - key: {body_json['token']}")
            response = table.delete_item(
                Key={
                    'p_key': 'app_key',
                    'token': body_json['token']
                },
                ReturnValues="ALL_OLD"
            )
            response_json = response.get('Attributes', None) 
            return response
        except Exception as e:
            raise e 

    def __validate_schema(self, schema, body_json, extn = False):
        try:
            if schema == "del_key":
                schema_obj = {
                    "type" : "object",
                    "properties" : {
                        "token" : {"type" : "string"},
                    },
                    "required": [ "token"]
                }              
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 
    
    def __generate_key(self):
        try:
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
            key_len = self.env['key_len']
            key = ""
            for x in range(0,key_len):
                key_char = random.choice(chars)
                key = key + key_char
            print("Here's your key: ",key)
            return key
        except Exception as e:
            raise Exception (f"Key generation failed - message: {e.message}") 
    