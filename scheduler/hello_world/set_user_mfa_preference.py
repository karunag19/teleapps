import boto3

access_token = "eyJraWQiOiJESzdJTkYyNWhUVWcwczJDWVVXcVNydnRvcGZiNllOakNudzFhNmk4eXZJPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIzN2RkODQ3NC1jZjNhLTQyMTgtODRlMy1mYTM2MGZiMTNhZTAiLCJldmVudF9pZCI6IjY1YTQ5YmI3LWNkM2ItNDE2Yy1hMzY5LTE0ZWVjYzQwYjJmMSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4gb3BlbmlkIHByb2ZpbGUgZW1haWwiLCJhdXRoX3RpbWUiOjE2NDU2OTY0NjIsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9mSDhEYng3QTAiLCJleHAiOjE2NDU3MDAwNjIsImlhdCI6MTY0NTY5NjQ2MiwidmVyc2lvbiI6MiwianRpIjoiZjk4NjZkODAtY2Q4NS00MzA4LWFiZDQtMDBjOWE1YWRhZGZmIiwiY2xpZW50X2lkIjoiMzVqMTVqOTVodmt0M251djFmbGhsN21lNmYiLCJ1c2VybmFtZSI6IjM3ZGQ4NDc0LWNmM2EtNDIxOC04NGUzLWZhMzYwZmIxM2FlMCJ9.GM6Smddkxfnj356LwSjHYvc8TN8D28c9NN5V_budTRjc4ygJkWdS0wptcbFIKfyPgrdWmNb2vzbtfECVfrxpCdpEiLEOZXVSYFdlXQDQp4VZkNJ5N8LJMBhpo3BjVAcER6arhDzeGFXRl99PKUVPdbWXm3hu-zFq7e82t145DbaxN6BxtB81lVy-K4l6aMkF764M-qR4f1ldSVaEt0j8IEJIEpGeejHjy128RZtovD0ZgrZhleDbbjvBPeUHhYrNhgxfWJ-RlH9E1BYKmyC97RfFCcsOI4YokRjLslB_HPALLd2kZTthXx75BckTemwMLP1WwUmkAFhyClD6B6Ge5g"
client = boto3.client('cognito-idp', region_name='ap-southeast-2')

try:
    response = client.set_user_mfa_preference(
        AccessToken = access_token,
        SoftwareTokenMfaSettings={
            'Enabled': True,
            'PreferredMfa': True
        },
    )
    print(response)
except Exception as e:
    print(f"ERROR: {e}")
