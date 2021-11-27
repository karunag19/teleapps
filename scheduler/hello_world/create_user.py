import logging
import boto3
from botocore.exceptions import ClientError
 
keyId = "AKIARA4JQP7Q2ZLBERH3"
sKeyId="0J8D/YG1cZgn8FJBiOo+5KE1vjgJQcxUJctH0KTu"
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

