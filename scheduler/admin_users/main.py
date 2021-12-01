import boto3
import json
import logging

from datetime import datetime
from dateutil import tz
from dateutil.tz import tzlocal

secret_dic = {}

def lambda_handler(event, context):

    try:
        client = get_client()
        if event['httpMethod'] == "GET":
            result = get_users(client)
        elif event['httpMethod'] == "POST" and event['path'] == "/users":
            param = json.loads(event['body'])
            result = create_user(client, param)
        elif event['httpMethod'] == "DELETE":
            param = json.loads(event['body'])
            result = delete_user(client, param)
        elif event['httpMethod'] == "POST" and event['path'] == "/password_reset":
            param = json.loads(event['body'])
            result = reset_password(client, param)  
        else:
            result = {"Error": "Invalid method type"}          

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

def get_client():
    try:
        global secret_dic
        secret_name = "karuna_secret_key"
        region = 'ap-southeast-2'

        client = boto3.client(
            'secretsmanager', 
            region_name=region,
        )
        secret_response = client.get_secret_value(
                SecretId=secret_name
            )

        secret_dic = json.loads(secret_response['SecretString'])
        keyId = secret_dic['CLIENT_ID']
        sKeyId = secret_dic['SECRET_KEY']

        client = boto3.client(
            'cognito-idp', 
            region_name=region,
            aws_access_key_id = keyId,
            aws_secret_access_key= sKeyId
        )
        return client
    except Exception as e:
        raise e       

def get_users(client):
    try:

        response = client.list_users(
            UserPoolId = 'ap-southeast-2_iWwopKLsU',
        )
        user_array = [] 
        for user in response['Users']:
            user_json = {}
            user_json = user
            # Karuna - change to utc time ---working code----
            # By default, it is showing utc time only, so we need not to convert the datetime.
            # d_local = user['UserCreateDate']
            # d_utc = d_local.astimezone(tz.tzutc())
            # user_json['UserCreateDate'] = str(d_utc)
            # ------------------------------------------------
            user_json['UserCreateDate'] = str(user['UserCreateDate'])
            user_json['UserLastModifiedDate'] = str(user['UserLastModifiedDate'])
            user_array.append(user_json)
        return user_array    

    except Exception as e:
        raise e        

def create_user(client, param):
    try:
        global secret_dic
        user_pool_id = secret_dic['USER_POOL_ID']
        response = client.admin_create_user(
            UserPoolId = user_pool_id,
            Username = param['email'],
            TemporaryPassword = param['temp_password'],
            UserAttributes = [{
                'Name': 'email',
                'Value': param['email']
            },
            {
                'Name': 'email_verified',
                'Value': 'True'
            }]
        )
        user_json = {}
        user_json = response['User']
        user_json['UserCreateDate'] = str(user_json['UserCreateDate'])
        user_json['UserLastModifiedDate'] = str(user_json['UserLastModifiedDate'])
        return user_json         
    except Exception as e:
        raise e

def delete_user(client, param):
    try:
        global secret_dic
        user_pool_id = secret_dic['USER_POOL_ID']
        response = client.admin_delete_user(
            UserPoolId = user_pool_id,
            Username = param['email'],
        )
        return response         
    except Exception as e:
        raise e        

def reset_password(client, param):
    try:
        global secret_dic
        user_pool_id = secret_dic['USER_POOL_ID']
        response = client.admin_reset_user_password(
            UserPoolId = user_pool_id,
            Username = param['email'],
        )
        return response
        # return {'name': 'Karuna'}         
    except Exception as e:
        raise e        