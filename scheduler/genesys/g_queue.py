import os
import base64, requests
import boto3
import json
import logging
import time
# from datetime import datetime
# from datetime import date
# from dateutil.relativedelta import relativedelta
# from dateutil import tz, parser
from boto3.dynamodb.conditions import Key, Attr
import botocore
from jsonschema import validate, ValidationError, Draft7Validator, validators
from decimal import Decimal

from concurrent.futures import ThreadPoolExecutor

genesys_environment = os.getenv('GENESYS_ENV', "mypurecloud.com.au") 
region = os.getenv('REGION', "ap-southeast-2") 
secret_client = os.getenv('SECRET_CLIENT', "demo-Secret") 
secret_token = os.getenv('SECRET_TOKEN', "demo-AccessToken") 
tbl_q_contacts = os.getenv('TBL_Q_Contacts', "demo_q_contacts") 
tbl_contact_details = os.getenv('TBL_Contact_Details', "demo_q_contact_details") 

token_url = f"https://login.{genesys_environment}/oauth/token"
queue_url = f"https://api.{genesys_environment}/api/v2/routing/queues?pageSize=500"
q_query_url = f"https://api.{genesys_environment}/api/v2/analytics/queues/observations/query?pageSize=100"
q_details = f"https://api.{genesys_environment}/api/v2/conversations/emails/"
skills_url = f"https://api.{genesys_environment}/api/v2/routing/skills?pageSize=500"
agents_url = f"https://api.{genesys_environment}/api/v2/users?pageSize=500"
# routing_url = f"https://api.{genesys_environment}/api/v2/users/AGENT_ID/routingskills" 
routing_url = f"https://api.{genesys_environment}/api/v2/users/AGENT_ID/routingskills/bulk" 

env = {
    "secret_client_key" : secret_client,
    "secret_token_key" : secret_token,
    "genesys_environment" : genesys_environment,
    "token_url" : token_url,
    "queue_url" : queue_url,
    "q_query_url": q_query_url,
    "q_details": q_details,
    "skills_url" : skills_url,
    "agents_url" : agents_url,
    "routing_url" : routing_url,
    "region" : region,
    "tbl_q_contacts": tbl_q_contacts,
    "tbl_contact_details": tbl_contact_details,
}

def lambda_handler(event, context):

    try:

        genesys = Lambda_Genesys_Queue(event, context, env)
        result = genesys.execute_method()
        return get_result(1, result)

    except Exception as e:
        logging.error(e)
        return get_result(0, str(e))

def get_result(success, data):
    result = {}
    result['success'] = success
    if success == 1:
        result['result'] = data
    else:
        result['error'] = data      
    final_result = {
        "statusCode":200,
        "body": json.dumps(result),
        'headers': {
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'OPTIONS,POST,GET,PUT,DELETE'
        }
    } 
    return final_result  




class Lambda_Genesys_Queue():
    

    def __init__(self, event, context, env):
        self.event = event
        self.context = context
        self.env = env

        try:
            print("INIT START")
            client = boto3.client(
                'secretsmanager', 
                region_name = self.env['region'],
            )
            secret_response = client.get_secret_value(
                    SecretId = self.env["secret_client_key"]
                )
            self.secret_client = json.loads(secret_response['SecretString'])
            secret_response = client.get_secret_value(
                    SecretId=self.env["secret_token_key"]
                )
            self.secret_token = json.loads(secret_response['SecretString'])  

            if self.secret_token['expires_time'] == '':
                token_ex_time = 0
            else:
                token_ex_time = int(self.secret_token['expires_time'])
            if time.time() >  token_ex_time:
                self.__update_token()   

            self.dynamodb = boto3.resource(
                'dynamodb', 
                region_name = self.env['region'],
            ) 
            print("INIT COMPLETED")
        except Exception as e:
            raise e 

    def execute_method(self):
        try:
            print(f"EVENT: {self.event}")
            if isinstance(self.event, dict) and "path" in self.event:
                param = self.event.get('path','').split('/')
                print(param)
                if len(param) < 3:
                    raise Exception(f"Invalid method name")
                handler_name = f"{self.event.get('httpMethod','').lower()}_{param[2]}"
                print(handler_name)
                handler = getattr(self, handler_name, None)
                if handler:
                    if len(param) > 3:
                        result = handler(param = param[3])
                    else:
                        result = handler()
                else:
                    raise Exception(f"Invalid method type({self.event.get('httpMethod','')}) or name({param[2]})")
                return result
            elif "detail-type" in self.event and self.event.get('detail-type') == "Scheduled Event":
                self.get_process_scheduled()

        except Exception as e:
            raise e

    def __update_token(self):
        try:
            # keyId = self.secret_client['CLIENT_ID']
            # sKeyId = self.secret_client['SECRET_KEY']
            access_token = self.__get_token()
            
            expires_in = access_token['expires_in']
            expires_time = int(time.time()) + int(expires_in)
            access_token['expires_time'] = expires_time

            self.secret_token = access_token

            client = boto3.client(
                'secretsmanager', 
                region_name=self.env["region"],
            )
            secret_response = client.put_secret_value(
                    SecretId=self.env['secret_token_key'],
                    SecretString=json.dumps(self.secret_token)
                )
            return secret_response    

        except Exception as e:
            raise e

    def __get_token(self):
        try:
            GENESYS_CLIENT_ID = self.secret_client['GENESYS_CLIENT_ID']
            GENESYS_SECRET = self.secret_client['GENESYS_SECRET']
            # Base64 encode the client ID and client secret
            authorization = base64.b64encode(bytes(GENESYS_CLIENT_ID + ":" + GENESYS_SECRET, "ISO-8859-1")).decode("ascii")
            # Prepare for POST /oauth/token request
            request_headers = {
                "Authorization": f"Basic {authorization}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            request_body = {
                "grant_type": "client_credentials"
            }

            # Get token
            response = requests.post(self.env["token_url"], data=request_body, headers=request_headers)
            print(f"response: {response}")
            # Check response
            if response.status_code == 200:
                print("Got token")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
            # Get JSON response body
            response_json = response.json()

            return  response_json      
        except Exception as e:
            raise e

    def get_queues(self):
        try:
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            
            response = requests.get(self.env["queue_url"], headers=requestHeaders)
            if response.status_code == 200:
                print("Got roles")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys users: { str(response.status_code) } - { response.reason }")

            return response.json()   
        except Exception as e:
            raise e 

    def post_get_qcontacts(self, param=None): 
        try:
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            self.__validate_schema("queues", body_json) 
            # q_array = ["4dd1d42e-d321-4177-b188-fb9882fbc106", "689324f1-9cea-452c-b0e5-e6b17c3cfdd8"]
            # q_array = body_json['queues']
            q_array = body_json.get('queues')
            b_reload = body_json.get('reload', False)
            print("STEP0")
            q_list_old =self.__get_q_list()
            flag_genesys = False
            if ((q_list_old == None) or (b_reload == True)):
                print("NO RECORD FOUND")
                flag_genesys = True
            else:
                response_epochtime = int(q_list_old['timestamp'])
                current_epochtime = int(time.time())
                if (current_epochtime-int(response_epochtime)) > 60:
                    flag_genesys = True
            
            if flag_genesys:
                response_json =self.__get_q_contacts_gc(q_array, q_list_old)
            else:
                response_json = self.__get_q_contacts_db()

            return response_json
        except Exception as e:
            raise e 

    # def get_contact_details(self, param=None): 
    #     try:
    #         table = self.dynamodb.Table(self.env['tbl_contact_details'])
    #         response = response = table.query(
    #             KeyConditionExpression=Key('queue_id').eq('app_key') 
    #         )
    #         response_json = response['Items']
    #         return response_json   
    #     except Exception as e:
    #         raise e 

    def __rep_decimal(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)

    def __get_q_list(self):
        try:
            table = self.dynamodb.Table(self.env['tbl_q_contacts'])
            response = table.get_item(
                Key={
                    'p_key': 'app_client',
                    'queue_id': 'now'
                }
            )
            if "Item" in response:
                response_json = response['Item']
                response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
                result = json.loads(response_json_temp) 
            else:
                result = None
            return result
        except Exception as e:
            raise e                 

    def __get_q_contacts_db(self):
        try:
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            response = table.scan()
            print("AFTER SCAN")
            # print(response)
            response_json = response['Items']
            response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
            return json.loads(response_json_temp) 
        except Exception as e:
            raise e

    def __get_q_contacts_gc(self, q_array, q_list_old):
        try:
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}",
                "Content-Type": "application/json"
            }
            request_body = self.__get_filter(q_array)
            print(self.env["q_query_url"])
            print(requestHeaders)
            print(request_body)
            response = requests.post(self.env["q_query_url"], json=request_body, headers=requestHeaders)
            print(f"response: {response}")

            if response.status_code == 200:
                print("Got token")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
            result = self.__process_result(response.json(), q_list_old)


            return result               
        except Exception as e:
            raise e     

    def __get_contacts_details(self, data):
        try:
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            detail_url = f"{self.env['q_details']}{data['conversation_id']}/messages"
            response = requests.get(detail_url, headers=requestHeaders)
            # print(f"response: {response}")

            if response.status_code == 200:
                print("Got token")
            else:
                print(f"Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
            response_json = response.json()
            response_json["queue_id"] = data['queue_id']
            response_json["conversation_id"] = data['conversation_id']
            self.__update_details(response_json)
            return response.json()               
        except Exception as e:
            raise e

    def __get_filter(self, q_array):
        try:
            filter_json = {}
            filter_json["detailMetrics"] = ["oWaiting", "oInteracting"]
            filter_json["metrics"] = ["oWaiting", "oInteracting"]
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
   

    def __process_result(self, result_json, q_list_old):
        try:
            epoch_time = int(time.time())
            data_json = []
            qlist_json = {}
            qlist_json['queues'] = []
            qlist_json['timestamp'] = epoch_time
            for queue in result_json["results"]:
                queueId = queue["group"]["queueId"]
                qlist_json['queues'].append(queueId)
                qlist_json[queueId] = {}
                qlist_json[queueId]['conversation'] = []
                for contact_metric in queue["data"]: 
                    metric = contact_metric["metric"]
                    if contact_metric["stats"]["count"] < 1:
                        continue
                    for contacts in contact_metric["observations"]:
                        contact_id = contacts["conversationId"]
                        qlist_json[queueId]['conversation'].append(contact_id)
                        conversation = {}
                        conversation["queue_id"] = queueId  #queue_id
                        conversation["contact_id"] = contact_id #conversation_id
                        conversation["data"] = contacts
                        conversation["details"] = {}
                        conversation["timestamp"] = epoch_time
                        conversation["metric"] = metric
                        data_json.append(conversation)

            print(qlist_json)
            self.__update_q_list(qlist_json)
            add_del_list = self.__compare_q_list(qlist_json, q_list_old)
            print("add_del_list")
            print(add_del_list)
            result = self.__update_q_table(data_json, add_del_list)
            return result
        except Exception as e:
            raise e   

    def __update_q_list(self, result_json):
        try:
            table = self.dynamodb.Table(self.env['tbl_q_contacts'])
            result_json['p_key'] = "app_client"
            result_json['queue_id'] = "now"
            response = table.put_item(
                Item=result_json
            )
            return result_json
        except Exception as e:
            raise e 

    def __compare_q_list(self, new_json, old_json):
        try:
            add_qlist = {}
            del_qlist = {}
            queues = []
            for queue_id in new_json['queues']:
                queues.append(queue_id)
                add_qlist[queue_id] = []
                del_qlist[queue_id] = []
                if queue_id not in new_json:
                    continue
                for conversation_id in new_json[queue_id]['conversation']:
                    if old_json == None:
                        add_qlist[queue_id].append(conversation_id)
                        continue
                    if conversation_id not in old_json[queue_id]['conversation']:
                        add_qlist[queue_id].append(conversation_id)
                if old_json != None:
                    for conversation_id in old_json[queue_id]['conversation']:
                        if conversation_id not in new_json[queue_id]['conversation']:
                            del_qlist[queue_id].append(conversation_id)
            result = {}
            result["add"] = add_qlist
            result["del"] = del_qlist
            result["queues"] = queues
            return result
        except Exception as e:
            raise e

    def __update_q_table(self, result_json, add_del_list):
        try:
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            map_assignment =[]
            with table.batch_writer() as batch:
                for conversation in result_json:
                    queue_id = conversation["queue_id"]
                    if conversation["contact_id"] in add_del_list["add"][queue_id]:
                        print(f"PUT ITEM: {conversation['contact_id']}")
                        batch.put_item(
                            Item=conversation
                        )
                        data = {}
                        data['queue_id'] = queue_id
                        data['conversation_id'] = conversation["contact_id"]
                        map_assignment.append(data)

                for queue_id in add_del_list["queues"]:
                    for conversation_id in add_del_list["del"][queue_id]:
                        print(f"DEL ITEM: {conversation_id}")
                        batch.delete_item(
                            Key={
                                'queue_id': queue_id,
                                'contact_id': conversation_id
                            }
                        )

            print(f"LENGTH: {len(map_assignment)}")
            with ThreadPoolExecutor(max_workers = 10) as executor:
                # task = executor.map(self.__get_contacts_details, map_assignment)
                for result in executor.map(self.__get_contacts_details, map_assignment):
                    print("RESULT")

            result = self.__get_q_contacts_db()
            # return result_json
            return result
        except Exception as e:
            raise e 

    # def __update_q_table_old(self, result_json):
    #     try:
    #         table = self.dynamodb.Table(self.env['tbl_contact_details'])
    #         with table.batch_writer() as batch:
    #             for conversation in result_json:
    #                 batch.put_item(
    #                     Item=conversation
    #                 )

    #         map_assignment =[]
    #         for conversation in result_json:
    #             data = {}
    #             data['queue_id'] = conversation['queue_id']
    #             data['conversation_id'] = conversation['data']['conversationId']
    #             map_assignment.append(data)
    #             # map_assignment.append(conversation_id)
    #         print(f"LENGTH: {len(map_assignment)}")
    #         with ThreadPoolExecutor(max_workers = 10) as executor:
    #             # task = executor.map(self.__get_contacts_details, map_assignment)
    #             for result in executor.map(self.__get_contacts_details, map_assignment):
    #                 print("RESULT")

    #         result = self.__get_q_contacts_db()
    #         # return result_json
    #         return result
    #     except Exception as e:
    #         raise e 

    def __update_details(self, result_json):
        try:
            print("__update_details")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
             
            response = table.update_item(
                Key={
                    'queue_id': result_json['queue_id'],
                    'contact_id': result_json['conversation_id'],
                },
                UpdateExpression="SET #s_column=:s_value",
                ExpressionAttributeNames={
                    "#s_column": "details"
                    },
                ExpressionAttributeValues={
                    ':s_value': result_json,
                }
            ) 

            return response
        except Exception as e:
            raise e        
    
    def __validate_schema(self, schema, body_json):
        try:
            if schema == "queues":
                schema_obj = {
                    "type" : "object",
                    "properties" : {     
                        "queues": {
                            "type": "array",
                            "items": {
                                "type" : "string"
                            }
                        }
                    },
                    "required": [ "queues"]
                }
            validate(instance=body_json, schema=schema_obj)
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 

    def get_test(self):
        try:

            # response = self.__update_details()
            response = self.__get_q_contacts_db()
            # q_array = ["4dd1d42e-d321-4177-b188-fb9882fbc106", "689324f1-9cea-452c-b0e5-e6b17c3cfdd8"]
            # response_json =self.__get_q_contacts_gc(q_array)
            # response_json = self.__get_contacts_details("01c3bb31-3c55-4e3b-916b-452966aca94d")
            return response
        except Exception as e:
            raise e                