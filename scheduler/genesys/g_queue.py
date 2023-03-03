import os
import base64, requests
import boto3
import json
import logging
import time
import datetime
import pytz
# from datetime import datetime
# from datetime import date
# from dateutil.relativedelta import relativedelta
# from dateutil import tz, parser
from boto3.dynamodb.conditions import Key, Attr
import botocore
from jsonschema import validate, ValidationError, Draft7Validator, validators
from decimal import Decimal

from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger()
# logging Level
# DEBUG - 10, INFO - 20, ERROR - 40
logger.setLevel(os.getenv('LOGLEVEL', 20))

genesys_environment = os.getenv('GENESYS_ENV', "mypurecloud.com.au") 
region = os.getenv('REGION', "ap-southeast-2") 
secret_client = os.getenv('SECRET_CLIENT', "demo-Secret") 
secret_token = os.getenv('SECRET_TOKEN', "demo-AccessToken") 
tbl_q_contacts = os.getenv('TBL_Q_Contacts', "demo_q_contacts") 
tbl_contact_details = os.getenv('TBL_Contact_Details', "demo_q_contact_details") 
contacts_query_interval = os.getenv('CON_QUERY_INTERVAL', 360) 
clear_cache_days = os.getenv('CLEAR_CACHE_DAYS', 0) # default (0) clear all the cache which is older than 1 day.
time_zone = os.getenv('TIME_ZONE', 'Australia/Sydney') # default australia time zone
# queue_query_interval = os.getenv('QUEUE_QUERY_INTERVAL', 600) 

token_url = f"https://login.{genesys_environment}/oauth/token"
queue_url = f"https://api.{genesys_environment}/api/v2/routing/queues?pageSize=500"
q_query_url = f"https://api.{genesys_environment}/api/v2/analytics/queues/observations/query?pageSize=100"
q_details = f"https://api.{genesys_environment}/api/v2/conversations/emails/"
skills_url = f"https://api.{genesys_environment}/api/v2/routing/skills?pageSize=500"
agents_url = f"https://api.{genesys_environment}/api/v2/users?pageSize=500"
# routing_url = f"https://api.{genesys_environment}/api/v2/users/AGENT_ID/routingskills" 
routing_url = f"https://api.{genesys_environment}/api/v2/users/AGENT_ID/routingskills/bulk" 
previous_agents_url = f"https://api.{genesys_environment}/api/v2/analytics/conversations/details?id=CONVERSATION_ID"
t_contact_url = f"https://api.{genesys_environment}/api/v2/analytics/conversations/details/query"

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
    "t_contact_url": t_contact_url,
    "previous_agents_url": previous_agents_url,
    "routing_url" : routing_url,
    "region" : region,
    "tbl_q_contacts": tbl_q_contacts,
    "tbl_contact_details": tbl_contact_details,
    "contacts_query_interval": contacts_query_interval, # default 60 sec.  -> query the queued contacts every 60 sec (1min.).
    # "queue_query_interval": queue_query_interval, # default 600 sec.  -> query the queued list every 600 sec (10min).
}

def lambda_handler(event, context):

    try:
        logger.info("lambda_handler.START")
        genesys = Lambda_Genesys_Queue(event, context, env)
        result = genesys.execute_method()
        logger.info("lambda_handler.END")
        return get_result(1, result)
    except Exception as e:
        logger.error(f"lambda_handler.Exception: {e}")
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
            logger.info("__init__.START")
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
            logger.info("__init__.END")
        except Exception as e:
            logger.error(f"__init__.Exception: {e}")
            raise e 

    def execute_method(self):
        try:
            logger.info("execute_method.START")
            if isinstance(self.event, dict) and "path" in self.event:
                param = self.event.get('path','').split('/')
                logger.info(f"execute_method.param: {param}")
                if len(param) < 3:
                    raise Exception(f"Invalid method name")
                handler_name = f"{self.event.get('httpMethod','').lower()}_{param[2]}"
                logger.info(handler_name)
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
                self.get_update_contact_details()
            logger.info("execute_method.END")
        except Exception as e:
            logger.error(f"execute_method.Exception: {e}")
            raise e

    def __update_token(self):
        try:
            logger.info("__update_token.START")
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
            logger.info("__update_token.END")
            return secret_response    

        except Exception as e:
            logger.error(f"__update_token.Exception: {e}")
            raise e

    def __get_token(self):
        try:
            logger.info("__get_token.START")
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
            logger.info(f"__get_token.response: {response}")
            # Check response
            if response.status_code == 200:
                logger.info("__get_token: Got 200 ok for get token")
            else:
                logger.info(f"__get_token.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
            # Get JSON response body
            response_json = response.json()
            logger.info("__get_token.END")
            return  response_json      
        except Exception as e:
            logger.error(f"__get_token.Exception: {e}")
            raise e

    def get_queues(self):
        try:
            logger.info("get_queues.START")
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            
            response = requests.get(self.env["queue_url"], headers=requestHeaders)
            if response.status_code == 200:
                logger.info("get_queues: Got 200 ok for get queues")
            else:
                logger.info(f"get_queues.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys users: { str(response.status_code) } - { response.reason }")
            logger.info("get_queues.END")
            # return response.json()   
            queues_json = response.json()
            filter_q = {}
            filter_q['entities'] = []
            q_array = []
            for queue in queues_json['entities']:
                q_name = queue['name']
                if q_name.startswith("EM_"):
                    filter_q['entities'].append(queue)
            return filter_q
        except Exception as e:
            logger.error(f"get_queues.Exception: {e}")
            raise e 

    def __get_q_array(self):
        try:
            logger.info("__get_q_array.START")
            queues_json = self.get_queues()
            q_array_details = {}
            q_array_details["q_id"] = []
            
            for queue in queues_json['entities']:
                q_array_details["q_id"].append(queue['id'])
                q_array_details[queue['name']]=queue['id']

            logger.debug(f"__get_q_array.q_array start with EM_: {q_array_details}")
            logger.info("__get_q_array.END")
            return q_array_details
        except Exception as e:
            logger.error(f"__get_q_array.Exception: {e}")
            raise e 

    def post_get_qcontacts(self, param=None): 
        try:
            logger.info("post_get_qcontacts.START")
            response_json = self.__get_q_contacts_db()
            logger.info("post_get_qcontacts.END")
            return response_json
        except Exception as e:
            logger.error(f"post_get_qcontacts.Exception: {e}")
            raise e 

    # Every minute this method is triggered by Amazon EventBridge.
    def get_update_contact_details(self): 
        try:
            logger.info("get_update_contact_details.START")
            
            contacts_list_db = self.__get_q_contacts_db()
            q_array_temp = self.__get_q_array()
            q_array = q_array_temp["q_id"]
            
            reschedule_list = self.__get_reschedule_list()
            reschedule_id = self.__get_reschedule_q_id(reschedule_list, q_array_temp)
                
            map_assignment = self.__get_agent_details_empty_list(contacts_list_db, q_array, reschedule_id) 
            conversation_id_list_old =  map_assignment["conversation_id_list_old"]
            map_assignment_details = map_assignment["details"]
            map_assignment_agent = map_assignment["agents"]

            # get current queue details from Genesys
            conversation_raw_new =self.__get_q_contacts_gc(q_array)
            
            # process the raw data from Genesys
            conversation_list_new = self.__process_result(conversation_raw_new)
            conversation_detail_list_new = conversation_list_new["conversation_detail_list_new"]
            conversation_id_list_new = conversation_list_new["conversation_id_list_new"] 
            truncated_list_new = conversation_list_new["truncated_list_new"] 

            # Compare the Conversation with old list
            conversation_add_del_list = self.__compare_conversation_list(conversation_id_list_new, conversation_id_list_old, truncated_list_new)

            # return {"c_list_new": conversation_list_new, "add_del_list": conversation_add_del_list, "detail": map_assignment_details}
            # Update new conversations in detail table
            result = self.__update_q_table(conversation_detail_list_new, conversation_add_del_list)
            
            map_assignment_truncat = []
            for queue_id in truncated_list_new["queues"]:
                data = {}
                data["queue_id"] = queue_id
                data["q_list_old"] = {}
                data["q_list_old"][queue_id] = conversation_id_list_old[queue_id]
                map_assignment_truncat.append(data)

            with ThreadPoolExecutor(max_workers = 5) as executor:
                for result in executor.map(self.__get_truncated_contacts_gc, map_assignment_truncat):
                    logger.info("get_update_contact_agents.END")

            # update empty details in contacts_details table.
            logger.info(f"get_update_contact_details.LENGTH: {len(map_assignment_details)}")
            with ThreadPoolExecutor(max_workers = 5) as executor:
                for result in executor.map(self.__get_contacts_details, map_assignment_details):
                    logger.info("get_update_contact_details.END")

            # update empty agents in contacts_details table.
            logger.info(f"get_update_contact_agents.LENGTH: {len(map_assignment_agent)}")
            with ThreadPoolExecutor(max_workers = 5) as executor:
                for result in executor.map(self.__get_previous_agent, map_assignment_agent):
                    logger.info("get_update_contact_agents.END")

            logger.info(f"get_update_contact_details.END")

            return {"result": "Success"}

            # # Below code is only for testing one Queue"
            # conversation_truncat_raw_new = self.__get_truncated_contacts_gc(map_assignment_truncat[0])
            # queue_id = map_assignment_truncat[0]["queue_id"]
            # conversation_truncat_list_new = self.__process_truncat_result(conversation_truncat_raw_new, queue_id)
            # conversation_trun_detail_list_new = conversation_truncat_list_new["conversation_trun_detail_list_new"]
            # conversation_truncat_id_list_new = conversation_truncat_list_new["conversation_trun_id_list_new"]
            
            # conversation_id_list_old_q = map_assignment_truncat[0]["q_list_old"]
            # conversation_truncat_add_del_list = self.__compare_truncat_list(conversation_truncat_id_list_new, conversation_id_list_old_q, queue_id)
            
            # result = self.__update_truncat_table(conversation_trun_detail_list_new, conversation_truncat_add_del_list)

        except Exception as e:
            logger.error(f"get_update_contact_details.Exception: {e}")
            raise e 


    def __get_agent_details_empty_list(self, contacts_list_db, q_array, reschedule_id): 
        try:
            logger.info("__get_agent_details_empty_list.START")
            logger.info(f"__get_agent_details_empty_list.reschedule_id: {reschedule_id}")
            map_assignment_details = []
            map_assignment_agent = []
            conversation_list_old = {}
            conversation_list_old['queues'] = []

            for queue_id in q_array:
                conversation_list_old['queues'].append(queue_id)
                conversation_list_old[queue_id] = {}
                conversation_list_old[queue_id]["oInteracting"] = {}
                conversation_list_old[queue_id]["oWaiting"] = {}
                conversation_list_old[queue_id]["oInteracting"]["conversation"] = []
                conversation_list_old[queue_id]["oInteracting"]["count"] = 0
                conversation_list_old[queue_id]["oWaiting"]["conversation"] = []
                conversation_list_old[queue_id]["oWaiting"]["count"] = 0

            for item in contacts_list_db:
                logger.debug(f"__get_agent_details_empty_list.item: {item}")
                conversation_list_old[item["queue_id"]][item["metric"]]["conversation"].append(item["contact_id"])
                detail = item["details"]
                if not detail:
                    # logger.info("detail is empty")
                    data = {}
                    data['queue_id'] = item["queue_id"]
                    data['conversation_id'] = item["contact_id"]
                    logger.info(f"Update Details: {data}")
                    map_assignment_details.append(data)
                previous_detail = item["previousAgent"]
                if previous_detail == None:
                    # logger.info("Preview agent is empty")
                    data = {}
                    data['queue_id'] = item["queue_id"]
                    data['conversation_id'] = item["contact_id"]
                    logger.info(f"Update Details: {data}")
                    if item["queue_id"] in reschedule_id:
                        map_assignment_agent.append(data)

            for queue_id in q_array:
                conversation_list_old[queue_id]["oInteracting"]["count"] = len(conversation_list_old[queue_id]["oInteracting"]["conversation"])
                conversation_list_old[queue_id]["oWaiting"]["count"] = len(conversation_list_old[queue_id]["oWaiting"]["conversation"])

            result = {}
            result["conversation_id_list_old"] = conversation_list_old
            result["details"] = map_assignment_details
            result["agents"] = map_assignment_agent
            return result

        except Exception as e:
            logger.error(f"__get_agent_details_empty_list.Exception: {e}")
            raise e 

    def __rep_decimal(self, obj): 
        if isinstance(obj, Decimal):
            return str(obj)
        raise TypeError("Object of type '%s' is not JSON serializable" % type(obj).__name__)

    def __get_q_list(self):
        try:
            logger.info("__get_q_list.START")
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
            logger.info("__get_q_list.END")
            return result
        except Exception as e:
            logger.error(f"__get_q_list.Exception: {e}")
            raise e                 

    def __get_reschedule_list(self):
        try:
            logger.info("__get_reschedule_list.START")
            table = self.dynamodb.Table(self.env['tbl_q_contacts'])
            response = table.get_item(
                Key={
                    'p_key': 'app_client',
                    'queue_id': 'reschedule'
                }
            )
            if "Item" in response:
                response_json = response['Item']['reschedule_q']
                response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
                result = json.loads(response_json_temp) 
            else:
                result = None
            logger.info("__get_reschedule_list.END")
            return result
        except Exception as e:
            logger.error(f"__get_reschedule_list.Exception: {e}")
            raise e 

    def __get_reschedule_q_id(self, reschedule_list, q_array_details):
        try:
            logger.info("__get_reschedule_q_id.START")
            reschedule_q_id = []
            for reschedule_name in reschedule_list:
                q_id = q_array_details.get(reschedule_name, None)
                if q_id != None:
                    reschedule_q_id.append(q_id)
            return reschedule_q_id
        except Exception as e:
            logger.error(f"__get_reschedule_q_id.Exception: {e}")
            raise e 

    def __get_q_contacts_db(self):
        try:
            logger.info("__get_q_contacts_db.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            response_json = []
            response = table.scan()
            logger.info("__get_q_contacts_db: AFTER SCAN")
            response_json = response['Items']

            while 'LastEvaluatedKey' in response:
                response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                for item in response['Items']:
                    response_json.append(item)


            logger.info(f"__get_q_contacts_db.LENGTH: {len(response_json)}")
            response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
            logger.info("__get_q_contacts_db.END")
            return json.loads(response_json_temp) 
        except Exception as e:
            logger.error(f"__get_q_contacts_db.Exception: {e}")
            raise e

    def __get_contacts_db_by_q(self, queue_id):
        try:
            logger.info("__get_contacts_db_by_q.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            response = table.query(
                KeyConditionExpression=Key('queue_id').eq(queue_id))
            print(response['Items'])
            if "Items" in response:
                response_json = response['Items']
                response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
                result = json.loads(response_json_temp) 


            # logger.info(f"__get_q_contacts_db.LENGTH: {len(response_json)}")
            # response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
            logger.info("__get_contacts_db_by_q.END")
            return result
        except Exception as e:
            logger.error(f"__get_contacts_db_by_q.Exception: {e}")
            raise e

    def __get_q_contacts_gc(self, q_array):
        try:
            logger.info("__get_q_contacts_gc.START")
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}",
                "Content-Type": "application/json"
            }
            request_body = self.__get_filter(q_array)
            response = requests.post(self.env["q_query_url"], json=request_body, headers=requestHeaders)

            if response.status_code == 200:
                logger.info("__get_q_contacts_gc: Got 200 ok to get contacts")
            else:
                logger.info(f"__get_q_contacts_gc.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")

            logger.info("__get_q_contacts_gc.END")
            return response.json()               
        except Exception as e:
            logger.error(f"__get_q_contacts_gc.Exception: {e}")
            raise e    

    def __get_truncated_contacts_gc(self, data):
        try:
            logger.info("__get_q__get_truncated_contacts_gc_contacts_gc.START")
            queue_id = data["queue_id"]
            q_list_old = data["q_list_old"]
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}",
                "Content-Type": "application/json"
            }
            page_n = 1
            f_count = 100
            result_total = {}
            result_total["conversations"] = []
            result_total["totalHits"] = 0
            while True:
                request_body = self.__get_truncat_filter(queue_id, page_n)
                response = requests.post(self.env["t_contact_url"], json=request_body, headers=requestHeaders)
                # logger.info(f"__get_truncated_contacts_gc.response: {response}")

                if response.status_code == 200:
                    logger.info("__get_truncated_contacts_gc: Got 200 ok to get contacts")
                else:
                    logger.info(f"__get_truncated_contacts_gc.Failure: { str(response.status_code) } - { response.reason }")
                    raise Exception(f"Failure to get Truncated Contacts: { str(response.status_code) } - { response.reason }")
                result = response
                result = response.json()
                for conversation in result["conversations"]:
                    result_total["conversations"].append(conversation)
                result_total["totalHits"] = result["totalHits"]

                logger.info(f"COUNT: {result['totalHits']}")
                logger.info(f"COUNT.f_count: {f_count}")
                if result['totalHits'] > f_count:
                    logger.info(f"GRATER THAN TOTALHITS")
                    page_n = page_n+1
                    f_count = f_count+100
                else:
                    logger.info(f"LESS THAN TOTALHITS")
                    break


            conversation_truncat_raw_new = result_total
            conversation_truncat_list_new = self.__process_truncat_result(conversation_truncat_raw_new, queue_id)
            conversation_truncat_detail_list_new = conversation_truncat_list_new["conversation_trun_detail_list_new"]
            conversation_truncat_id_list_new = conversation_truncat_list_new["conversation_trun_id_list_new"]

            conversation_id_list_old_q = q_list_old
            conversation_truncat_add_del_list = self.__compare_truncat_list(conversation_truncat_id_list_new, conversation_id_list_old_q, queue_id)
            
            result = self.__update_truncat_table(conversation_truncat_detail_list_new, conversation_truncat_add_del_list)
            logger.info("__get_truncated_contacts_gc.END")
            return result               
        except Exception as e:
            logger.error(f"__get_truncated_contacts_gc.Exception: {e}")
            raise e  

    def __get_contacts_details(self, data):
        try:
            logger.info("__get_contacts_details.START")
            
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            detail_url = f"{self.env['q_details']}{data['conversation_id']}/messages"
            response = requests.get(detail_url, headers=requestHeaders)
            # logger.info(f"response: {response}")

            if response.status_code == 200:
                logger.info("__get_contacts_details: Got 200 OK for get contacts details.")
            else:
                logger.info(f"__get_contacts_details.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
            response_json = response.json()
            response_json["queue_id"] = data['queue_id']
            response_json["conversation_id"] = data['conversation_id']
            result = self.__get_parse_agent_details(response_json)
            self.__update_details(result)
            logger.info("__get_contacts_details.END")
            return result 
            # return response_json               
        except Exception as e:
            logger.error(f"__get_contacts_details.Exception: {e}")
            raise e

    def __get_previous_agent(self, data):
        try:
            logger.info("__get_previous_agent.START")
            logger.info(f"__get_previous_agent.data: {data}")

            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            p_agent_url_temp = self.env['previous_agents_url']
            p_agent_url = p_agent_url_temp.replace("CONVERSATION_ID", data['conversation_id'])
            response = requests.get(p_agent_url, headers=requestHeaders)
            logger.info(f"response: {response}")

            if response.status_code == 200:
                logger.info("__get_previous_agent: Got 200 OK for get contacts details.")
            else:
                logger.info(f"__get_previous_agent.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Contact travel details: { str(response.status_code) } - { response.reason }")
            response_json = response.json()
            return_data = {}
            return_data["queue_id"] = data['queue_id']
            return_data["conversation_id"] = data['conversation_id']

            previousAgent = self.__get_previous_agent_only(response_json)
            logger.info(f"__get_previous_agent.previousAgent: {previousAgent}")
            
            if previousAgent != None:
                return_data["previousAgent"] = previousAgent
                self.__update_agents(return_data)

            logger.info(f"__get_previous_agent.return_data: {return_data}")
            logger.info("__get_previous_agent.END")
            return return_data              
        except Exception as e:
            logger.error(f"__get_previous_agent.Exception: {e}")
            raise e

    def __get_filter(self, q_array):
        try:
            logger.info("__get_filter.START")
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
            logger.info("__get_filter.END")
            return filter_json
        except Exception as e:
            logger.error(f"__get_filter.Exception: {e}")
            raise e    

    def __get_truncat_filter(self, queue_id, page_n):
        try:
            logger.info("__get_truncat_filter.START")
            d_today = datetime.date.today()
            d_tomorrow = d_today + datetime.timedelta(days=1)
            d_last30d = d_tomorrow + datetime.timedelta(days=-30)
            filter_json = {}
            filter_json["interval"] = f"{d_last30d}T00:00:00.000Z/{d_tomorrow}T22:00:00.000Z"
            filter_json["order"] = "desc"
            filter_json["orderBy"] = "conversationStart"

            filter_json["paging"] = {}
            filter_json["paging"]["pageSize"] = 100  
            filter_json["paging"]["pageNumber"] = page_n
            
            filter_json["segmentFilters"] = []
            segment_temp = {}
            segment_temp["type"] = "and"
            segment_temp["predicates"] = []
            pred_temp = {}
            pred_temp["type"] = "dimension"
            pred_temp["dimension"] = "purpose"
            pred_temp["operator"] = "matches"
            pred_temp["value"] = "acd"
            segment_temp["predicates"].append(pred_temp)
            pred_temp = {}
            pred_temp["type"] = "dimension"
            pred_temp["dimension"] = "queueId"
            pred_temp["operator"] = "matches"
            pred_temp["value"] = queue_id
            segment_temp["predicates"].append(pred_temp)
            pred_temp = {}
            pred_temp["type"] = "dimension"
            pred_temp["dimension"] = "segmentType"
            pred_temp["operator"] = "matches"
            pred_temp["value"] = "interact"
            segment_temp["predicates"].append(pred_temp)
            pred_temp = {}
            pred_temp["type"] = "dimension"
            pred_temp["dimension"] = "segmentEnd"
            pred_temp["operator"] = "notExists"
            pred_temp["value"] = None
            segment_temp["predicates"].append(pred_temp)
            filter_json["segmentFilters"].append(segment_temp)

            filter_json["conversationFilters"] = []
            conver_temp = {}
            conver_temp["type"] = "and"
            conver_temp["predicates"] = []
            pred_temp = {}
            pred_temp["type"] = "dimension"
            pred_temp["dimension"] = "conversationEnd"
            pred_temp["operator"] = "notExists"
            pred_temp["value"] = None
            conver_temp["predicates"].append(pred_temp)
            filter_json["conversationFilters"].append(conver_temp)

            return filter_json
        except Exception as e:
            logger.error(f"__get_truncat_filter.Exception: {e}")
            raise e    

    def __process_result(self, result_json):
        try:
            logger.info("__process_result.START")
            epoch_time = int(time.time())
            data_json = []
            qlist_json = {}
            qlist_json['queues'] = []
            qlist_json['timestamp'] = epoch_time
            qlist_json['total_count'] = {}
            qlist_json['total_count']["oWaiting"] = 0
            qlist_json['total_count']["oInteracting"] = 0
            
            truncated_json = {}
            truncated_json["queues"] = []
            for queue in result_json["results"]:
                queueId = queue["group"]["queueId"]
                qlist_json['queues'].append(queueId)
                qlist_json[queueId] = {}
                # qlist_json[queueId]['conversation'] = []
                for contact_metric in queue["data"]: 
                    # logger.info(f"__process_result.contact_metric: {contact_metric}")
                    count = contact_metric["stats"]["count"]
                    is_truncated = False
                    if count > 0:
                        is_truncated = bool(contact_metric["truncated"])
                    if is_truncated:
                        truncated_json["queues"].append(queueId) 
                        truncated_json[queueId] = {}
                        truncated_json[queueId]["count"] = count

                    metric = contact_metric["metric"]
                    qlist_json[queueId][metric] = {}
                    qlist_json[queueId][metric]['conversation'] = [] 
                    qlist_json[queueId][metric]['conversation_count'] = 0 
                    qlist_json[queueId][metric]['count'] = count                   
                    if contact_metric["stats"]["count"] < 1:
                        continue 
                    for contacts in contact_metric["observations"]:
                        contact_id = contacts["conversationId"]
                        # qlist_json[queueId]['conversation'].append(contact_id)
                        qlist_json[queueId][metric]['conversation'].append(contact_id)
                        conversation = {}
                        conversation["queue_id"] = queueId  #queue_id
                        conversation["contact_id"] = contact_id #conversation_id
                        conversation["data"] = contacts
                        conversation["details"] = {}
                        conversation["previousAgent"] = None
                        conversation["timestamp"] = epoch_time
                        conversation["metric"] = metric
                        data_json.append(conversation)
                    qlist_json[queueId][metric]['conversation_count'] = len(qlist_json[queueId][metric]['conversation'])
                    qlist_json['total_count'][metric] = qlist_json['total_count'][metric] + qlist_json[queueId][metric]['count']

            result = {}
            result["conversation_detail_list_new"] = data_json
            result["conversation_id_list_new"] = qlist_json
            result["truncated_list_new"] = truncated_json
            return result

            # # logger.info(f"__process_result.qlist_json: {qlist_json}")
            # # self.__update_q_list(qlist_json)
            # # add_del_list = self.__compare_conversation_list(qlist_json, q_list_old, truncated_json)
            # # # logger.info(f"__process_result.add_del_list: {add_del_list}")
            # # result = self.__update_q_table(data_json, add_del_list)
            # logger.info(f"__process_result.truncated_json: {truncated_json}")
            # logger.info("__process_result.END")
            # return {"result": result, "truncat": truncated_json} 
        except Exception as e:
            logger.error(f"__process_result.Exception: {e}")
            raise e   

    def __process_truncat_result(self, result_json, queue_id):
        try:
            logger.info("__process_truncat_result.START")
            logger.info(f"__process_truncat_result.queue_id:{queue_id}")
            epoch_time = int(time.time())

            data_json = []
            c_list_json = {}
            c_list_json[queue_id] = {}
            c_list_json[queue_id]["oWaiting"] = {}
            c_list_json[queue_id]["oWaiting"]['conversation'] = []  
            logger.info("__process_truncat_result.1")
            for conversation in result_json["conversations"]:
                logger.info("__process_truncat_result.2")
                c_list_json[queue_id]["oWaiting"]['conversation'].append(conversation["conversationId"])
                con_json = {}
                con_json["queue_id"] = queue_id
                con_json["contact_id"] = conversation["conversationId"]
                con_json["data"] = {}
                con_json["data"]["addressFrom"] = ""
                con_json["data"]["addressTo"] = ""
                con_json["data"]["conversationId"] = conversation["conversationId"]
                con_json["data"]["direction"] = ""
                con_json["data"]["observationDate"] = ""
                con_json["data"]["participantName"] = ""
                con_json["data"]["routingPriority"] = 0
                con_json["data"]["sessionId"] = ""
                con_json["details"] = {}
                con_json["previousAgent"] = None
                con_json["timestamp"] = epoch_time
                con_json["metric"] = "oWaiting"
                
                for participant in conversation["participants"]:
                    logger.info("__process_truncat_result.3")
                    if participant["purpose"] == "external":
                        if "participantName" in participant:
                            con_json["data"]["participantName"] = participant["participantName"]
                    if participant["purpose"] == "acd":
                        for session in participant["sessions"]:
                            con_json["data"]["addressFrom"] = session["addressFrom"]
                            con_json["data"]["addressTo"] = session["addressTo"]
                            con_json["data"]["direction"] = session["direction"]
                            con_json["data"]["sessionId"] = session["sessionId"]
                            for metric in session["metrics"]:
                                con_json["data"]["observationDate"] = metric["emitDate"]




                data_json.append(con_json)

            result = {}
            result["conversation_trun_detail_list_new"] = data_json
            result["conversation_trun_id_list_new"] = c_list_json            
            return result


            add_del_list = self.__compare_truncat_list(c_list_json, q_list_old, queue_id)
            
            # # logger.info(f"__process_truncat_result.add_del_list: {add_del_list}")
            # result = self.__update_truncat_table(data_json, add_del_list)
            # logger.info(f"__process_truncat_result.truncated_json: {truncated_json}")
            # logger.info("__process_truncat_result.END")
            result_json = {}
            # result_json["Conversation"] = data_json
            # result_json["c_list_json"] = c_list_json
            result_json["__update_q_table"] = result
            
            return result_json
        except Exception as e:
            logger.error(f"__process_truncat_result.Exception: {e}")
            raise e   

    def __update_q_list(self, result_json):
        try:
            logger.info("__update_q_list.START")
            table = self.dynamodb.Table(self.env['tbl_q_contacts'])
            result_json['p_key'] = "app_client"
            result_json['queue_id'] = "now"
            response = table.put_item(
                Item=result_json
            )
            # logger.info(f"__update_q_list.result: {result_json}")
            logger.info("__update_q_list.END")
            return result_json
        except Exception as e:
            logger.error(f"__update_q_list.Exception: {e}")
            raise e 

    def __compare_conversation_list(self, new_json, old_json, truncated_json):
        try:
            logger.info("__compare_conversation_list.START")
            add_qlist = {}
            del_qlist = {}
            queues = []

            for queue_id in new_json['queues']:
                queues.append(queue_id)
                add_qlist[queue_id] = []
                del_qlist[queue_id] = []

                if queue_id in truncated_json["queues"]:
                    logger.debug(f"__compare_conversation_list.FOR LOOP CONTINUE {queue_id}")
                    continue
                for conversation_id in new_json[queue_id]['oWaiting']['conversation']:
                    # logger.debug(f"__compare_conversation_list.conversation_id: {conversation_id}")
                    if old_json == None:
                        if conversation_id not in add_qlist[queue_id]:
                            add_qlist[queue_id].append(conversation_id)
                        continue
                    if conversation_id not in old_json[queue_id]['oWaiting']['conversation']:
                        if conversation_id not in add_qlist[queue_id]:
                            add_qlist[queue_id].append(conversation_id)
                for conversation_id in new_json[queue_id]['oInteracting']['conversation']:
                    if old_json == None:
                        if conversation_id not in add_qlist[queue_id]:
                            add_qlist[queue_id].append(conversation_id)
                        continue
                    if conversation_id not in old_json[queue_id]['oInteracting']['conversation']:
                        if conversation_id not in add_qlist[queue_id]:
                            add_qlist[queue_id].append(conversation_id)

                if old_json != None:
                    for conversation_id in old_json[queue_id]['oWaiting']['conversation']:
                        if (conversation_id not in new_json[queue_id]['oWaiting']['conversation']):
                            if conversation_id not in del_qlist[queue_id]:
                                del_qlist[queue_id].append(conversation_id)
                    for conversation_id in old_json[queue_id]['oInteracting']['conversation']:
                        if (conversation_id not in new_json[queue_id]['oInteracting']['conversation']):
                             if conversation_id not in del_qlist[queue_id]:
                                del_qlist[queue_id].append(conversation_id)
            result = {}
            result["add"] = add_qlist
            result["del"] = del_qlist
            result["queues"] = queues
            logger.info("__compare_conversation_list.END")
            return result
        except Exception as e:
            logger.error(f"__compare_conversation_list.Exception: {e}")
            raise e

    def __compare_truncat_list(self, new_json, old_json, queue_id):
        try:
            logger.info("__compare_truncat_list.START")
            add_qlist = {}
            del_qlist = {}

            add_qlist[queue_id] = []
            del_qlist[queue_id] = []

            for conversation_id in new_json[queue_id]['oWaiting']['conversation']:
                if old_json == None:
                    if conversation_id not in add_qlist[queue_id]:
                        add_qlist[queue_id].append(conversation_id)
                    continue
                if conversation_id not in old_json[queue_id]['oWaiting']['conversation']:
                    if conversation_id not in add_qlist[queue_id]:
                        add_qlist[queue_id].append(conversation_id)
            
            for conversation_id in old_json[queue_id]['oWaiting']['conversation']:
                if (conversation_id not in new_json[queue_id]['oWaiting']['conversation']):
                    if conversation_id not in del_qlist[queue_id]:
                        del_qlist[queue_id].append(conversation_id)

            result = {}
            result["queues"] = []
            result["queues"].append(queue_id)
            result["add"] = add_qlist
            result["del"] = del_qlist
            logger.info("__compare_truncat_list.END")
            return result
        except Exception as e:
            logger.error(f"__compare_truncat_list.Exception: {e}")
            raise e

    def __update_q_table(self, result_json, add_del_list):
        try:
            logger.info("__update_q_table.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            with table.batch_writer() as batch:
                for queue_id in add_del_list["queues"]:
                    for conversation_id in add_del_list["del"][queue_id]:
                        logger.info(f"__update_q_table.DEL ITEM: {conversation_id}")
                        batch.delete_item(
                            Key={
                                'queue_id': queue_id,
                                'contact_id': conversation_id
                            }
                        )

            with table.batch_writer() as batch:
                for conversation in result_json:
                    queue_id = conversation["queue_id"]
                    if conversation["contact_id"] in add_del_list["add"][queue_id]:
                        logger.info(f"__update_q_table.PUT ITEM: {conversation['contact_id']}")
                        batch.put_item(
                            Item=conversation
                        )

            logger.info("__update_q_table.END")
            return add_del_list
        except Exception as e:
            logger.error(f"__update_q_table.Exception: {e}")
            raise e 

    def __update_truncat_table(self, result_json, add_del_list):
        try:
            logger.info("__update_truncat_table.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            with table.batch_writer() as batch:
                for queue_id in add_del_list["queues"]:
                    for conversation_id in add_del_list["del"][queue_id]:
                        logger.info(f"__update_truncat_table.DEL ITEM: {conversation_id}")
                        batch.delete_item(
                            Key={
                                'queue_id': queue_id,
                                'contact_id': conversation_id
                            }
                        )
            logger.info("__update_truncat_table.AFTER DELETE")
            with table.batch_writer() as batch:
                for conversation in result_json:
                    queue_id = conversation["queue_id"]
                    if conversation["contact_id"] in add_del_list["add"][queue_id]:
                        logger.info(f"__update_truncat_table.PUT ITEM: {conversation['contact_id']}")
                        batch.put_item(
                            Item=conversation
                        )

            # result = self.__get_q_contacts_db()
            logger.info("__update_truncat_table.END")
            result = {}
            result["add_del_list"] = add_del_list
            return result
        except Exception as e:
            logger.error(f"__update_truncat_table.Exception: {e}")
            raise e 

    def __update_details(self, result_json):
        try:
            logger.info("__update_details.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
             
            response = table.update_item(
                Key={
                    'queue_id': result_json['queue_id'],
                    'contact_id': result_json['conversation_id'],
                },
                ConditionExpression='attribute_exists(queue_id) AND attribute_exists(contact_id)',
                UpdateExpression="SET #s_column=:s_value",
                
                ExpressionAttributeNames={
                    "#s_column": "details"
                    },
                ExpressionAttributeValues={
                    ':s_value': result_json,
                }
            ) 
            logger.info("__update_details.END")
            return response
        except Exception as e:
            logger.warning(f"__update_details.Exception: {e}")
                    

    def __update_agents(self, result_json):
        try:
            logger.info("__update_agents.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])

            response = table.update_item(
                Key={
                    'queue_id': result_json['queue_id'],
                    'contact_id': result_json['conversation_id'],
                },
                ConditionExpression='attribute_exists(queue_id) AND attribute_exists(contact_id)',
                UpdateExpression="SET #s_column=:s_value",
                ExpressionAttributeNames={
                    "#s_column": "previousAgent"
                    },
                ExpressionAttributeValues={
                    ':s_value': result_json["previousAgent"],
                }
            ) 
            logger.info("__update_agents.END")
            return response
        except Exception as e:
            logger.warning(f"__update_agents.Exception: {e}")
             

    def __get_previous_agent_only(self, result_json):
        try:
            previous_agent = None
            logger.info("__get_previous_agent_only.START")
            for conv in result_json["conversations"]:
                for part in conv["participants"]:
                    if part["purpose"] == "agent":
                        if "participantName" in part:
                            previous_agent = part["participantName"]

            logger.info("__get_previous_agent_only.END")
            return previous_agent
        except Exception as e:
            logger.error(f"__get_previous_agent_only.Exception: {e}")
            raise e

    def __get_parse_agent_details(self, result_json):
        try:
            data_details = {}
            data_details["entities"] = []
            detail_json = {}
            logger.info("__get_parse_agent_details.START")
            for entitie in result_json["entities"]:
                detail_json = {}
                detail_json["id"] = entitie["id"]
                detail_json["to"] = []
                for to_list in entitie["to"]:
                    to_json = {}
                    to_json["email"] = to_list["email"]
                    if "name" in to_list:
                        to_json["name"] = to_list["name"]
                    detail_json["to"].append(to_json)
                if "subject" in entitie:
                    detail_json["subject"] = entitie["subject"]
                detail_json["time"] = entitie["time"]
            data_details["entities"].append(detail_json)
            data_details["queue_id"] = result_json['queue_id']
            data_details["conversation_id"] = result_json['conversation_id']
            logger.info("__get_parse_agent_details.END")
            return data_details
            # return result_json
        except Exception as e:
            logger.error(f"__get_parse_agent_details.Exception: {e}")
            raise e

    def __validate_schema(self, schema, body_json):
        try:
            logger.info("__validate_schema.START")
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
            logger.info("__validate_schema.END")
        except ValidationError as e:
            raise Exception (f"Invalid json input - message: {e.message}, Error at: {e.json_path}, Valid Schema: {e.schema}") 

    # Karuna - delete the rows of contact_details table for clean up
    def __clear_cache(self):
        try:
            logger.info("__clear_cache.START")
            
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            response = table.scan()
            response_json = response['Items']
            with table.batch_writer() as batch:
                for contact in response_json:
                    batch.delete_item(
                        Key={
                            'queue_id': contact['queue_id'],
                            'contact_id': contact['contact_id']
                        }
                    )
            logger.info("__clear_cache.END")
        except Exception as e:
            logger.error(f"__clear_cache.Exception: {e}")
            raise e  

    # Karuna - delete the rows (- 1 day) of contact_details table for clean up
    def __clear_cache_by_date(self):
        try:
            logger.info("__clear_cache_by_date.START")
            AS_TimeZone = pytz.timezone(time_zone)
            local_dt = datetime.datetime.now(AS_TimeZone)
            logger.info(f"__clear_cache_by_date.local_dt: {local_dt}")
            logger.info(f"__clear_cache_by_date.hour: {local_dt.hour}")
            logger.info(f"__clear_cache_by_date.minute: {local_dt.minute}")
            if local_dt.hour == 23 and local_dt.minute > 58:
                logger.info(f"__clear_cache_by_date.START CLEAR CACHE: {local_dt}")
                table = self.dynamodb.Table(self.env['tbl_contact_details'])
                date = datetime.datetime.now() - datetime.timedelta(days=clear_cache_days)
                dt_epoch_time = datetime.datetime(date.year,date.month,date.day,0,0).timestamp()
                logger.info(f"__clear_cache_by_date.dt_epoch_time: {dt_epoch_time}")
                response = table.scan(FilterExpression=Attr("timestamp").lte(int(dt_epoch_time)) )
                response_json = response['Items']
                logger.info(f"__clear_cache_by_date.LENGTH: {len(response_json)}")
                with table.batch_writer() as batch:
                    for contact in response_json:
                        batch.delete_item(
                            Key={
                                'queue_id': contact['queue_id'],
                                'contact_id': contact['contact_id']
                            }
                        )
                logger.info("__clear_cache_by_date.END")
                response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
                return json.loads(response_json_temp)
            return "Cache NOT cleared"
        except Exception as e:
            logger.error(f"__clear_cache_by_date.Exception: {e}")
            raise e  

    def get_test(self):
        try:
            # # Get RAW Truncated List from Genesys based on Q ID
            # data = {}
            # data["queue_id"] = "ee496fc2-0b8d-4ff2-b3e5-734eafd2fdea"
            # data["q_list_old"] ={}
            # response = self.__get_truncated_contacts_gc(data)

            # # Get Conversation Details for Update Details
            # data = {}
            # data['queue_id'] = "ee496fc2-0b8d-4ff2-b3e5-734eafd2fdea"
            # data['conversation_id'] = "1a50922e-d4be-409d-a2be-98f756523703"
            # result = self.__get_contacts_details(data)
            # response = result
            
            # # Update Agents: 
            # data = {}
            # data['queue_id'] = "5787747c-4150-404f-9b0f-f72c8d351a19"
            # data['conversation_id'] = "10375e6c-d7da-4b7a-84bc-159236a6b90b"
            # result = self.__get_previous_agent(data)
            # logger.info(f"__get_previous_agent.result: {result}")
            # response = result
            
            # # Get Q' id only
            # q_array_temp = self.__get_q_array()
            # q_array = q_array_temp["q_id"]
            # response = q_array

            # # Get Q' details
            # q_array_temp = self.__get_q_array()
            # response = q_array_temp

            # # Get scheduled list
            # response = self.__get_reschedule_list()

            # # Get reschedule id
            # q_array_temp = self.__get_q_array()
            # reschedule_list = self.__get_reschedule_list()
            # response = self.__get_reschedule_q_id(reschedule_list, q_array_temp)
            
            # Get Q Contact from Genesys
            # q_array_temp = self.__get_q_array()
            # q_array = q_array_temp["q_id"]
            # q_list_old = {"temp":""}
            # conversation_raw_new =self.__get_q_contacts_gc(q_array)
            # conversation_list_new = self.__process_result(conversation_raw_new)
            # response = conversation_list_new

            # # Get conversation list in DB
            # contacts_list_db = self.__get_q_contacts_db()
            # q_array_temp = self.__get_q_array()
            # q_array = q_array_temp["q_id"]
            # reschedule_list = self.__get_reschedule_list()
            # reschedule_id = self.__get_reschedule_q_id(reschedule_list, q_array_temp)
            # map_assignment = self.__get_agent_details_empty_list(contacts_list_db, q_array, reschedule_id) 
            # response = map_assignment

            # Clear cache by date
            response = self.__clear_cache_by_date()
            
            # Temp:
            # response = self.__get_contacts_db_by_q("4dd1d42e-d321-4177-b188-fb9882fbc106")
            # logger.info("get_test.END")
            return response
        except Exception as e:
            logger.error(f"get_test.Exception: {e}")
            raise e                