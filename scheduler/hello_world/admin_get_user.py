import logging
import boto3
from botocore.exceptions import ClientError
import os
from dotenv import load_dotenv
load_dotenv()

keyId = os.environ.get("CLIENT_ID")
sKeyId=os.environ.get("SECRET_KEY")
region = 'ap-southeast-2'
 
try:
    client = boto3.client(
        'cognito-idp', 
        region_name=region,
        aws_access_key_id = keyId,
        aws_secret_access_key= sKeyId
    )

    response = client.admin_get_user(
        UserPoolId = 'ap-southeast-2_iWwopKLsU',
        Username = 'karunag19@gmail.com'
    )
    print(response)
except ClientError as e:
    logging.error(e)

