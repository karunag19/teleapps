import requests

print("Start")

def __get_filter(q_array):
    try:
        filter_json = {}
        filter_json["detailMetrics"] = ["oWaiting", "oInteracting"]
        filter_json["metrics"] = ["oWaiting", "oInteracting"]
        # filter_json["detailMetrics"] = ["oWaiting"]
        # filter_json["metrics"] = ["oWaiting"]
        filter_json["filter"] = {}
        filter_json["filter"]["type"] = "and"
        filter_json["filter"]["clauses"] = []

        predicates1_json = {}
        predicates1_json["type"] = "or"
        predicates1_json["predicates"] = []
        
        for queue_id in q_array:
            dimension1_json = {}
            dimension1_json["dimension"] = "queueId"
            dimension1_json["value"] = queue_id
            predicates1_json["predicates"].append(dimension1_json)

        predicates2_json = {}
        predicates2_json["type"] = "or"
        predicates2_json["predicates"] = []
        dimension2_json = {}
        dimension2_json["dimension"] = "mediaType"
        dimension2_json["value"] = "email"
        predicates2_json["predicates"].append(dimension2_json)

        filter_json["filter"]["clauses"].append(predicates1_json)
        filter_json["filter"]["clauses"].append(predicates2_json)

        return filter_json
    except Exception as e:
        raise e    

def __get_contacts_details():
    try:
        print("__get_contacts_details")
        borg = True

        genesys_environment = "mypurecloud.com.au" 
        q_query_url = f"https://api.{genesys_environment}/api/v2/analytics/queues/observations/query?pageSize=100"
        token_type = "bearer"
        access_token_borg = "erVcKwbHHPckv5efdFKrrMQbiBimRvuDXnlOO5V5nCYb7DD2Ux7WXQ5HFu2BxNCJj5a7x-NrMPuRd_v94AGUPw"
        access_token_demo = "ul9XxC9zBRVzmYZGGiyGzAhekKdK7oDOcusPbd4_XSnZjt5aGrpc66d5gnGiwixpgnuF-aHMB4gcnYuLs755jg"
        # q_array_demo = ['e3531d9d-c5d5-42ef-80c4-fbfc2ef02277', '6438fe73-fa24-4671-90e2-be63be56d7a4', '4a8cda40-863d-4ba6-9891-e204ae23667c', '4dd1d42e-d321-4177-b188-fb9882fbc106', '4b843af6-e5dc-48b0-b943-a6f1d9b9aec3']
        q_array_demo = ['4dd1d42e-d321-4177-b188-fb9882fbc106']
        # q_array_borg = ['29a2f439-b26c-4a24-8408-326b2e64daae', 'c45858fa-ab72-42cf-92c3-91006d14c96d', '6a7becc9-2d60-4866-8a7a-68c6dbb956df', '3e4a153a-f548-48a0-8f5e-2a0e3a941ad4', '2b6edcf6-5ca7-4a05-8397-0543610e532f', '59e11130-2112-4aec-98cc-b98f84c8b6c5', '09607b0a-f5c4-4846-8f3e-143efda91d15', '1a42b9cf-1d09-4d0c-af93-32ff9758315a', 'b95f5817-5fc7-4b73-bccf-6fcd5dc4c3d3', '1440265e-6273-42ad-8f8f-d52028ff1e45', '6b55a63b-6054-4991-84cc-158c18baa392', 'cf6f239d-58a9-46d2-b450-65dbf83dd67b', '33e610ac-f750-4e3e-b83c-f2da610886f6', '036e290c-02b4-4baa-a134-31db70f4f38a', '38b30fe6-6900-47fb-b5e6-52b067e65a40', 'ee496fc2-0b8d-4ff2-b3e5-734eafd2fdea', 'e1c74636-8f1b-4323-bdb8-9d5551e4bc98', '2a147466-7611-4994-a86d-d62215cb7885', 'b631066e-f03b-48d3-9ec8-542f837cba64', 'de078034-0cb9-4433-a723-fb70e827ff84', 'ce3ae4e7-4097-4167-9437-a5ce9d34d392', 'bb96e64f-22ba-4ae1-90e0-4883da528f61', 'b70bd946-ba87-483b-bcfd-e245e2194417', '26009a2d-2605-4315-9165-fd9ca459f6b6', 'f4e2397f-b178-442c-8441-3d6d2be99f4a', 'a874037f-e8be-4714-941f-a162b71dc390', '00c946ac-d0f3-44d9-a1bc-30a892b25dae', 'ceff018c-d628-4558-a790-2198f8c6ea08', 'd53f46ff-1b5d-4492-a922-abd471c1a4b7', 'c0e6baab-3eb8-4ea3-b5c1-bd88d96e6fca', '5c3de963-3b88-46bd-807f-329903f5091a', 'cbd021c4-224f-451d-9b5f-8b53e284ae2b', '0ac7fce0-65d6-4c55-94e5-e3dc28cba2e5', '6f055d98-6d69-4c52-8986-f04198998b5a', '7a6ed55f-edd6-4074-b1b6-070308207cb7', '16575077-8100-4bd4-a90a-37cacc9f420b', 'ad3acabd-88d2-421f-928e-f10b52ea26f2', '0a140840-0473-4a19-985f-4d35b7a34dd7', '1cf44943-c55b-4130-a209-a0934d31c937', 'e31141f8-bd7d-4c0b-97a9-30b2332b5c74', 'd46e08ba-a50d-4e7c-94d8-bdf36c13f58a', '089a9408-2ed6-4c67-9e10-ce5180d4e80d', '16de02f8-aed1-4603-8e81-ada38d4e6fee', '05b34768-cafe-4a3a-b581-5cc6a2e31e06', '39f9e0d7-6dbb-4dc3-9f68-35226f06964c', 'a6a30336-acee-4f8e-b1ed-8a1f7da43a3e', 'b6151b8b-a664-430a-afd5-9122d4f775b1', 'd3289cc0-1b00-46c4-a75d-0ebf716f3610', '673a1ba1-009a-48f6-9702-e0ea8812d535']
        q_array_borg = ['29a2f439-b26c-4a24-8408-326b2e64daae']
        
        if borg:
            access_token = access_token_borg
            q_array = q_array_demo
        else:
            access_token = access_token_demo
            q_array = q_array_demo           

        requestHeaders = {
            "Authorization": f"{ token_type } {access_token}",
            "Content-Type": "application/json"
        }
        request_body = __get_filter(q_array)
        print(q_query_url)
        print(requestHeaders)
        print(request_body)
        response = requests.post(q_query_url, json=request_body, headers=requestHeaders)
        print(f"response: {response}")

        if response.status_code == 200:
            print("Got token")
        else:
            print(f"Failure: { str(response.status_code) } - { response.reason }")
            raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
        print("response.json()")
        print(response.json())
              
    except Exception as e:
        raise e

__get_contacts_details()
print("End")