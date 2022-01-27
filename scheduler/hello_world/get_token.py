import boto3

client = boto3.client('cognito-idp', region_name='ap-southeast-2')

response = client.initiate_auth(
    # sparza -> user pool
    # ClientId = '4chgoojglj4m0qi9gh7fuelpp7',
    
    # sparza_mfa -> user pool
    ClientId = '71p4njcmv8hb9lrb6jmfs35dls',
    
    
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
        'USERNAME': 'karunag19@gmail.com',
        'PASSWORD': 'Karuna@123'

    }

)
print(f"Access Token: {response['AuthenticationResult']['AccessToken']} ")
print(f"Access Token: {response['AuthenticationResult']['RefreshToken']} ")