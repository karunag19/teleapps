import boto3

access_token = "eyJraWQiOiJxMzRzMml3YTc5NnZsemlmTVdpeHpXQ0xmYnpkXC9kdzhPblFcL0xZeHQrMFk9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIyOTExNGFiZS05MmVlLTQ2MDktODBiYy02MzM1NWMxYmVmNjQiLCJldmVudF9pZCI6IjBlZDc1ZjE3LTc2N2EtNGE2Yy05NmEzLWZjYTc3ZDYxYzA0ZSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4gb3BlbmlkIGVtYWlsIiwiYXV0aF90aW1lIjoxNjQyODMyOTM2LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfenZqUUlPSU1kIiwiZXhwIjoxNjQyODM2NTM2LCJpYXQiOjE2NDI4MzI5MzYsInZlcnNpb24iOjIsImp0aSI6IjlmZmY2MGVhLTFlMTEtNGU1Yi1hYzAwLWMxNmE1OWY0YTQ5NiIsImNsaWVudF9pZCI6IjcxcDRuamNtdjhoYjlscmI2am1mczM1ZGxzIiwidXNlcm5hbWUiOiIyOTExNGFiZS05MmVlLTQ2MDktODBiYy02MzM1NWMxYmVmNjQifQ.WeTEfJNlxAdi47otn8qUmxx_fvSPXCiGcAhVtnSG5pZUKhTUB69KtZH845mbLD0OvMN0m7xQs-_Rc0aoMJPDADIpfQ55KgVfKexY167SHRx6lxWyQUEhUj8zuL01tNIgSECb_-vLIZ07wBs-YprbphnI6dCNlzy2CPcFVyUv4LexH9cZXNP-oq7XwbFxo0fwBjKNjyjL4xUDcIB0QXAwa7zGNVCXDXFSkM2B2FrqiAqoDnnVTY93xOsC-xIepgk3QMkeunflV9xlSwinWh5W_PXhSGBogrYyJ_OQOB4PBPWVN2s6smILSlaVmDZFBr4VJBpcDNxpw2fnEySb6NEGFg"
client = boto3.client('cognito-idp', region_name='ap-southeast-2')

try:
    response = client.associate_software_token(
        AccessToken = access_token,
    )
    print(response)
except:
    print("ERROR")
