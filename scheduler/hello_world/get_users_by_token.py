import boto3

access_token = "eyJraWQiOiJESzdJTkYyNWhUVWcwczJDWVVXcVNydnRvcGZiNllOakNudzFhNmk4eXZJPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhMGU0ZWM5Ni1kZjA5LTQwMDAtOTkyNy00MTlkMDk5YzVhNTEiLCJjb2duaXRvOmdyb3VwcyI6WyJBZG1pbnMiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiBvcGVuaWQgcHJvZmlsZSBlbWFpbCIsImF1dGhfdGltZSI6MTY0NjAyOTk0OSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmFwLXNvdXRoZWFzdC0yLmFtYXpvbmF3cy5jb21cL2FwLXNvdXRoZWFzdC0yX2ZIOERieDdBMCIsImV4cCI6MTY0NjAzMzU0OSwiaWF0IjoxNjQ2MDI5OTQ5LCJ2ZXJzaW9uIjoyLCJqdGkiOiI4NjRhN2E1NS02MGY2LTQxMTctYmQ4Yi0xYzk5NDA0N2U3OTAiLCJjbGllbnRfaWQiOiIzNWoxNWo5NWh2a3QzbnV2MWZsaGw3bWU2ZiIsInVzZXJuYW1lIjoiYTBlNGVjOTYtZGYwOS00MDAwLTk5MjctNDE5ZDA5OWM1YTUxIn0.F7uxme7ead-AUIDPVy5w4FxgUfvrUfPI1DibY9ogPuWnrGXPLCEpsk1-Cy16XlkChRArXLMgVAYbyGrDTx9JyCycskB-bNEFnzi-SyIgHZRPacNqGojkDHMCze91OKGIetkZqwCz3rP4hBkKJKzTGnX2CZTluy31gEotcRUY5cJenZUrPMR_KC1OmGlBiXx-0qWQQ2nvpy4mb5PC7njjqhkThdCu9GeBgLJ2UKD73LAZ-tugt1B1qyrxQ1UETFkFh6iqdOpFM2ZxeaugQuIIzMHLfpgq_DdpzZ2Ds02HnmgrYWecFnWNmRMX4hUgt9DjBMRy3VZ4pPkjediOqPFA9A"
# access_token_postmen = "eyJraWQiOiJITUxMTjJBcVwvbCtGOFQ2eDhZOWpia25xb05UbEVHMDJiakd1NkNqQzg4az0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI5OGU5OTFjMi02MzQxLTQ0NGQtODEyYS04YmQ3YjIxNzI2NzkiLCJldmVudF9pZCI6IjQ4OGEzZGFlLTZiYjctNDZjYy04Y2VmLTE4NTFjZmY1NTIyMCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoib3BlbmlkIGVtYWlsIiwiYXV0aF90aW1lIjoxNjM3OTE2NTYzLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTIuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTJfaVd3b3BLTHNVIiwiZXhwIjoxNjM3OTIwMTYzLCJpYXQiOjE2Mzc5MTY1NjMsInZlcnNpb24iOjIsImp0aSI6ImI5MDlkMWNlLWY3ZGYtNGU5Yy1iZDEwLTEyOGI0ZWU1YzdlNiIsImNsaWVudF9pZCI6IjFjMWJwZGZscTIzZ2w4OHNzbzFjcmx2a281IiwidXNlcm5hbWUiOiI5OGU5OTFjMi02MzQxLTQ0NGQtODEyYS04YmQ3YjIxNzI2NzkifQ.uYZSv6norJJusMyModp8hQk1Ah4zT3teE-4TG-kKiM90sgrGgRbO-a0OcCFIdRHa1FQxBsk7hYvbFmhk1duvuxIqZBvNYFZWXI8vJqDpAb2uWJJLIjTA-Mz_b1w4ufOdybkxBJie0kbHn9OG_tUtwm3NjADC7Xwo9cXRwF2umawHih-7mRCiA75m8Gmwu733_pls-hfkvqCFEc2yyuMiC_IunjJiCZV4JO5Ln2x2x-u2kI77lg2j_39IphL6gWBqNwoW5uwabWqpruCZ1QfnJpaLoxVkpUpeJ7VL7IeuOl1AHHb_5S_r8akYu6P9TPD10UA9sJBWO8WASjJJ4aMH7g"
client = boto3.client('cognito-idp', region_name='ap-southeast-2')

try:
    response = client.get_user(
        AccessToken = access_token
        # AccessToken = access_token_postmen

    )

    print(response['UserAttributes'])
except:
    print("ERROR")
