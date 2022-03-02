import boto3
import json
import logging
import os

region = os.getenv('REGION', "ap-southeast-2") 
tbl_api_key = os.getenv('TBL_API_KEY', "demo_api_key") 
acc_number = os.getenv('ACC_NUMBER', "070618480609") 
api_deploy_url = os.getenv('API_DEPLOY_URL', "stel4fk8w7") 

env = {
    "region" : region,
    "tbl_api_key" : tbl_api_key
    "acc_number": acc_number
    "api_deploy_url": api_deploy_url
}

def lambda_handler(event, context):
    try: 
        genesys = Lambda_Auth(event, context, env)
        token = event['Authorization']
        result = genesys.validate(token)
        return get_result(env, result)

    except Exception as e:
        logging.error(e)
        return get_result(0, str(e))

def get_result(env, result):
     
    if result:
        auth = 'Allow'
    else:
        auth = 'Deny'
    
    authResponse = { 
        "principalId": "abc123", 
        "policyDocument": { 
            "Version": "2012-10-17", 
            "Statement": [
                {
                    "Action": "execute-api:Invoke", 
                    "Resource": [
                        f"arn:aws:execute-api:us-east-1:{env[acc_number]}:{env[api_deploy_url]}/*/**"
                        ], 
                    "Effect": auth
                }
            ] 
        }
    }
    return authResponse

class Lambda_Auth():

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

    def validate(self, token):
        try:
            table = self.dynamodb.Table(self.env['tbl_api_key'])  
            response = table.get_item(
                Key={
                    'p_key': 'app_key',
                    'key': token
                }
            )
            result = True
            if "Item" not in response:
                False
            return result   
        except Exception as e:
            raise e 