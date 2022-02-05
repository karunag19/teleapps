import boto3
import json
import logging
import os

from datetime import datetime
from dateutil import tz
from dateutil.tz import tzlocal
from jsonschema import validate, ValidationError

secret_dic = {}
region = os.getenv('REGION', "ap-southeast-2") 
secret_client = os.getenv('SECRET_CLIENT', "karuna_secret_key") 
user_pool_id = os.getenv('USER_POOL_ID', "ap-southeast-2_iWwopKLsU") 

env = {
    "secret_client_key" : secret_client,
    "region" : region,
    "user_pool_id" : user_pool_id
}

def lambda_handler(event, context):
    try:

        genesys = Lambda_Cognito(event, context, env)
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

class Lambda_Cognito():

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

            self.client = boto3.client(
                'cognito-idp', 
                region_name=self.env['region'],
                # aws_access_key_id = self.secret_client['CLIENT_ID'],
                # aws_secret_access_key= self.secret_client['SECRET_KEY']
            )

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
    def post_software_token(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            # self.__validate_schema("user_create", body_json)  
            # print("After __validate_schema")             
            response = self.client.associate_software_token(
                AccessToken = body_json['access_token'],
            )
            return response    

        except Exception as e:
            raise e

    def get_users(self):
        try:
            response = self.client.list_users(
                UserPoolId = self.env['user_pool_id'],
            )
            user_array = [] 
            for user in response['Users']:
                user_json = {}
                user_json = user
                user_json['UserCreateDate'] = str(user['UserCreateDate'])
                user_json['UserLastModifiedDate'] = str(user['UserLastModifiedDate'])
                user_array.append(user_json)
            return user_array    

        except Exception as e:
            raise e             

    def post_users(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("user_create", body_json)  
            print("After __validate_schema")          
            response = self.client.admin_create_user(
                UserPoolId = self.env['user_pool_id'],
                Username = body_json['email'],
                TemporaryPassword = body_json['temp_password'],
                UserAttributes = [{
                    'Name': 'email',
                    'Value': body_json['email']
                },
                {
                    'Name': 'email_verified',
                    'Value': 'True'
                }]
            )
            print("After res[pmse")
            print(response)
            user_json = {}
            user_json = response['User']
            user_json['UserCreateDate'] = str(user_json['UserCreateDate'])
            user_json['UserLastModifiedDate'] = str(user_json['UserLastModifiedDate'])
            return user_json         
        except Exception as e:
            raise e            

    def delete_users(self):
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("user_delete", body_json) 
            response = self.client.admin_delete_user(
                UserPoolId = self.env['user_pool_id'],
                Username = body_json['email'],
            )
            return response         
        except Exception as e:
            raise e 

    def __validate_schema(self, schema_name, body_json):
        try:
            print("START __validate_schema")
            if schema_name == "user_create":
                schema = {
                    "type" : "object",
                    "properties" : {
                        "email" : {"type" : "string"},
                        "temp_password" : {"type" : "string"},
                    },
                    "required": [ "email", "temp_password"]
                }
                validate(instance=body_json, schema=schema)
            if schema_name == "user_delete":
                schema = {
                    "type" : "object",
                    "properties" : {
                        "email" : {"type" : "string"},
                    },
                    "required": [ "email"]
                }
                validate(instance=body_json, schema=schema)
            print("END __validate_schema")
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 

    # def post_reset_password(self):
    #     try:
    #         if self.event.get('body', None) == None:
    #             raise Exception(f"You have to pass the data as JSON in body")
    #         body_json = json.loads(self.event.get('body'))
    #         self.__validate_schema("user_delete", body_json) 
    #         response = self.client.admin_reset_user_password(
    #             UserPoolId = self.env['user_pool_id'],
    #             Username = body_json['email'],
    #         )
    #         return response
    #     except Exception as e:
    #         raise e       