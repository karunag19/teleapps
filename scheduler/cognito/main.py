import boto3
import json
import logging
import os

from datetime import datetime
from dateutil import tz
from dateutil.tz import tzlocal
from jsonschema import validate, ValidationError

logger = logging.getLogger()
# logging Level
# DEBUG - 10, INFO - 20, ERROR - 40
logger.setLevel(os.getenv('LOGLEVEL', 20))

# secret_dic = {}
region = os.getenv('REGION', "ap-southeast-2") 
secret_client = os.getenv('SECRET_CLIENT', "demo-Secret")  
user_pool_id = os.getenv('USER_POOL_ID', "ap-southeast-2_fH8Dbx7A0")  # demo-UserPool -> Pool Id

env = {
    "secret_client_key" : secret_client,
    "region" : region,
    "user_pool_id" : user_pool_id
}

def lambda_handler(event, context):
    try: 
        logger.info("lambda_handler.START")
        genesys = Lambda_Cognito(event, context, env)
        result = genesys.execute_method()
        logger.info("lambda_handler.END")
        return get_result(1, result)

    except Exception as e:
        logger.error(f"lambda_handler.Exception: {e}")
        return get_result(0, str(e))

def get_result(success, data):
    logger.info("get_result.START")
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
    logger.info("get_result.END")
    return final_result        

class Lambda_Cognito():

    def __init__(self, event, context, env):
        self.event = event
        self.context = context
        self.env = env

        try:
            logger.info("__init__.START")
            client = boto3.client(
                'secretsmanager', 
                region_name = self.env['region'],
            )
            logger.info(f"__init__.secret_client: {self.env['secret_client_key']}")
            secret_response = client.get_secret_value(
                    SecretId = self.env["secret_client_key"]
                )
            logger.info("__init__: after secret_client response")
            self.secret_client = json.loads(secret_response['SecretString'])

            self.client = boto3.client(
                'cognito-idp', 
                region_name=self.env['region'],
                # aws_access_key_id = self.secret_client['CLIENT_ID'],
                # aws_secret_access_key= self.secret_client['SECRET_KEY']
            )
            logger.info("__init__.END")
        except Exception as e:
            logger.error(f"__init__.Exception: {e}")
            raise e 

    def execute_method(self):
        try:
            logger.info("execute_method.START")
            if isinstance(self.event, dict) and "path" in self.event:
                param = self.event.get('path','').split('/')
                logger.info(f"execute_method.param: {param}")
                if len(param) < 3:
                    raise Exception(f"Invalid method name")
                handler_name = f"{self.event.get('httpMethod','').lower()}_{param[2]}"
                logger.info(f"execute_method.handler_name: {handler_name}")
                handler = getattr(self, handler_name, None)
                if handler:
                    if len(param) > 3:
                        result = handler(param = param[3])
                    else:
                        result = handler()
                else:
                    raise Exception(f"Invalid method type({self.event.get('httpMethod','')}) or name({param[2]})")
                logger.info("execute_method.END")
                return result
        except Exception as e:
            logger.error(f"execute_method.Exception: {e}")
            raise e        

    def post_software_token(self):
        try:
            logger.info("post_software_token.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            # self.__validate_schema("user_create", body_json)  
            # logger.info("post_software_token: After __validate_schema")             
            response = self.client.associate_software_token(
                AccessToken = body_json['access_token'],
            )
            logger.info("post_software_token.END")
            return response    

        except Exception as e:
            logger.error(f"post_software_token.Exception: {e}")
            raise e

    def get_users(self):
        try:
            logger.info("get_users.START")
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
            logger.info("get_users.END")
            return user_array    

        except Exception as e:
            logger.error(f"get_users.Exception: {e}")
            raise e             

    def post_get_user(self):
        try:
            logger.info("post_get_user.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("user_detail", body_json)  
            logger.info("post_get_user: After __validate_schema")  
            response = self.client.admin_get_user(
                UserPoolId = self.env['user_pool_id'],
                Username = body_json['email'],
            )
            response['UserCreateDate'] = str(response['UserCreateDate'])
            response['UserLastModifiedDate'] = str(response['UserLastModifiedDate'])
            logger.info("post_get_user.END")
            return response    

        except Exception as e:
            logger.error(f"post_get_user.Exception: {e}")
            raise e  

    def post_users(self):
        try:
            logger.info("post_users.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("user_create", body_json)  
            logger.info("post_users: After __validate_schema")          
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
            logger.info(f"post_users.response: {response}")
            user_json = {}
            user_json = response['User']
            user_json['UserCreateDate'] = str(user_json['UserCreateDate'])
            user_json['UserLastModifiedDate'] = str(user_json['UserLastModifiedDate'])
            logger.info("post_users.END")
            return user_json         
        except Exception as e:
            logger.error(f"post_users.Exception: {e}")
            raise e            

    def delete_users(self):
        try:
            logger.info("delete_users.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("user_delete", body_json) 
            response = self.client.admin_delete_user(
                UserPoolId = self.env['user_pool_id'],
                Username = body_json['email'],
            )
            logger.info("delete_users.END")
            return response         
        except Exception as e:
            logger.error(f"delete_users.Exception: {e}")
            raise e 

    def __validate_schema(self, schema_name, body_json):
        try:
            logger.info("__validate_schema.START")
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
            if schema_name == "user_detail":
                schema = {
                    "type" : "object",
                    "properties" : {
                        "email" : {"type" : "string"},
                    },
                    "required": [ "email"]
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
            if schema_name == "mfa_step1":
                schema = {
                    "type" : "object",
                    "properties" : {
                        "access_token" : {"type" : "string"},
                    },
                    "required": ["access_token"]
                }
                validate(instance=body_json, schema=schema)
            if schema_name == "mfa_step2":
                schema = {
                    "type" : "object",
                    "properties" : {
                        "access_token" : {"type" : "string"},
                        "code" : {"type" : "string"},
                    },
                    "required": ["access_token", "code"]
                }
                validate(instance=body_json, schema=schema)
            logger.info("__validate_schema.END")
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 

    def post_mfa_step1(self):
        try:
            logger.info("post_mfa_step1.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("mfa_step1", body_json) 
            response = self.client.associate_software_token(
                AccessToken = body_json['access_token'],
            )
            logger.info("post_mfa_step1.END")
            return response
        except Exception as e:
            logger.error(f"post_mfa_step1.Exception: {e}")
            raise e       

    def post_mfa_step2(self):
        try:
            logger.info("post_mfa_step2.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("mfa_step2", body_json) 
            response = self.client.verify_software_token(
                AccessToken = body_json['access_token'],
                UserCode = body_json['code']
            )
            logger.info("post_mfa_step2.END")
            return response
        except Exception as e:
            logger.error(f"post_mfa_step2.Exception: {e}")
            raise e 

    def post_mfa_step3(self):
        try:
            logger.info("post_mfa_step3.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("mfa_step1", body_json) 
            response = self.client.set_user_mfa_preference(
                AccessToken = body_json['access_token'],
                SoftwareTokenMfaSettings={
                    'Enabled': True,
                    'PreferredMfa': True
                },
            )
            logger.info("post_mfa_step3.END")
            return response
        except Exception as e:
            logger.error(f"post_mfa_step3.Exception: {e}")
            raise e 

    def post_disable_mfa(self):
        try:
            logger.info("post_disable_mfa.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("mfa_step1", body_json) 
            response = self.client.set_user_mfa_preference(
                AccessToken = body_json['access_token'],
                SoftwareTokenMfaSettings={
                    'Enabled': False,
                    'PreferredMfa': False
                },
            )
            logger.info("post_disable_mfa.END")
            return response
        except Exception as e:
            logger.error(f"post_disable_mfa.Exception: {e}")
            raise e 

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
    #         logger.error(f"lambda_handler.Exception: {e}")
    #         raise e  