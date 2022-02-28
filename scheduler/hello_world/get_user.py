import boto3

user_pool_id = "ap-southeast-2_fH8Dbx7A0"
username = "karuna.g@teleapps.com.au"
client = boto3.client('cognito-idp', region_name='ap-southeast-2')

try:
    response = client.admin_get_user(
        UserPoolId=user_pool_id,
        Username=username
    )
    print(response)
except ClientError as e:
    print(e)
