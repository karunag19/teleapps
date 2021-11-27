import boto3

client = boto3.client('cognito-idp', region_name='ap-southeast-2')

response = client.initiate_auth(
    ClientId = '4chgoojglj4m0qi9gh7fuelpp7',
    # ClientSecret = '10ftntfboem1oalqf5c8afu20ocd0alou70srhlha9vjboue7ao7',
    AuthFlow='USER_PASSWORD_AUTH',
    AuthParameters={
        'USERNAME': 'karunag19@gmail.com',
        'PASSWORD': 'Karuna@123'

    }

)
print(f"Access Token: {response['AuthenticationResult']['AccessToken']} ")
print(f"Access Token: {response['AuthenticationResult']['RefreshToken']} ")