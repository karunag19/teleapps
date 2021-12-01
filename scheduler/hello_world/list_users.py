import logging
import json
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
load_dotenv()

# keyId = os.environ.get("CLIENT_ID")
# sKeyId=os.environ.get("SECRET_KEY")
secret_name = "karuna_secret_key"
region = 'ap-southeast-2'

try:
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

    response = client.list_users(
        UserPoolId = 'ap-southeast-2_iWwopKLsU',
    )
    # print(response['Users'][0]['UserCreateDate'])
    user_array = [] 
    for user in response['Users']:
        user_json = {}
        user_json['user'] = user
        user_json['user']['UserCreateDate'] = str(user['UserCreateDate'])
        user_json['user']['UserLastModifiedDate'] = str(user['UserLastModifiedDate'])
        print(user_json['user']['UserCreateDate'])
        user_array.append(user_json)
    print(json.dumps(user_array))

except ClientError as e:
    logging.error(e)

