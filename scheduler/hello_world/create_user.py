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

    response = client.admin_create_user(
        UserPoolId = 'ap-southeast-2_iWwopKLsU',
        Username = 'karunag19@live.in',
        TemporaryPassword = 'Karuna@123',
        UserAttributes = [{
            'Name': 'email',
            'Value': 'karunag19@live.in'

        },
        {
            'Name': 'email_verified',
            'Value': 'True'

        }]
    )
    print(response)
except ClientError as e:
    logging.error(e)

