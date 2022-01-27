import boto3

access_token = "eyJraWQiOiJxMzRzMml3YTc5NnZsemlmTVdpeHpXQ0xmYnpkXC9kdzhPblFcL0xZeHQrMFk9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIyOTExNGFiZS05MmVlLTQ2MDktODBiYy02MzM1NWMxYmVmNjQiLCJldmVudF9pZCI6ImRjZjIwZGFmLTAzNGEtNDY4Mi05ODk5LTBjOTFkZGMyMTZiMCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4gb3BlbmlkIGVtYWlsIiwiYXV0aF90aW1lIjoxNjQyODM5MTgyLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfenZqUUlPSU1kIiwiZXhwIjoxNjQyODQyNzgyLCJpYXQiOjE2NDI4MzkxODIsInZlcnNpb24iOjIsImp0aSI6IjIzZDIyNzE1LWY0YmQtNDYyOC05NTBhLWRkOTg4NzA2NGQ5MSIsImNsaWVudF9pZCI6IjcxcDRuamNtdjhoYjlscmI2am1mczM1ZGxzIiwidXNlcm5hbWUiOiIyOTExNGFiZS05MmVlLTQ2MDktODBiYy02MzM1NWMxYmVmNjQifQ.W_hzfe5prrmtYWTP5VcsvAEtbxGMuFoVdPqo-f94VrOEvQeZKBKtSfvvpqpHuZ74FdsMsHfWN7KJrC0w4n1wq3OU9ZjRAP_e3suzLIcH7XDzEEf9ByS_JPCSmUo2pBrFXdOweZAoV1GGwK9hPPCTbXN0Za6-q45lAhZMoPpJTyzz-EDU0tcbsi4E3m_DZRWJjxpr1i8n9qO5w8iaGKluuqiz3378YFhuV-Yuj64k3FCsxO2afRgF8LcAdtYgnWPBDlvbuaw9c-eYgleSb-q_HNeLdpxXMk9eDODO-vz-vlzdEQLmQNXbndLmxgl2cujZP_BQgYwYl2-M4CPCY89xMw"
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
