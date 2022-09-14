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
contacts_query_interval = os.getenv('CON_QUERY_INTERVAL', 120) 
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
            q_array = []
            for queue in queues_json['entities']:
                q_array.append(queue['id'])

            logger.debug(f"__get_q_array.q_array start with EM_: {q_array}")
            logger.info("__get_q_array.END")
            return q_array
        except Exception as e:
            logger.error(f"__get_q_array.Exception: {e}")
            raise e 

    def post_get_qcontacts(self, param=None): 
        try:
            logger.info("post_get_qcontacts.START")
            if self.event.get('body', None) == None:
                raise Exception(f"You have to pass the data as JSON in body")
            body_json = json.loads(self.event.get('body'))
            # self.__validate_schema("queues", body_json) 

            b_clear_cache = body_json.get('clear_cache', False)
            b_reload = body_json.get('reload', False)
            # karuna - due to slow, we set the reload always False
            b_reload = False
            b_clear_cache = False
            # --------------karuna reload end -----
            
            
            if b_clear_cache:
                q_list_old = None
                # Karuna - due to slow in delete the mails in table, I am comment this below line.
                # self.__clear_cache()
            else:
                q_list_old =self.__get_q_list()

            flag_genesys = False
            if ((q_list_old == None) or (b_reload == True)):
                logger.info("post_get_qcontacts: NO RECORD FOUND/ reload:true")
                q_array = self.__get_q_array()
                flag_genesys = True
            else:
                response_epochtime = int(q_list_old['timestamp'])
                q_array = q_list_old['queues']
                current_epochtime = int(time.time())
                if (current_epochtime-int(response_epochtime)) > self.env['contacts_query_interval']:
                    flag_genesys = True
            
            if flag_genesys:
                result =self.__get_q_contacts_gc(q_array, q_list_old)
                response_json = result['result']
            else:
                response_json = self.__get_q_contacts_db()
            logger.info("post_get_qcontacts.END")
            return response_json
        except Exception as e:
            logger.error(f"post_get_qcontacts.Exception: {e}")
            raise e 

    def get_update_contact_details(self): 
        try:
            logger.info("get_update_contact_details.START")
            response_json = self.__get_q_contacts_db()  
            map_assignment = []
            map_assignment_agent = []

            q_list_old_detail = {}
            q_list_old_detail['queues'] = []
            q_array = self.__get_q_array()
            for queue_id in q_array:
                q_list_old_detail['queues'].append(queue_id)
                q_list_old_detail[queue_id] = {}
                q_list_old_detail[queue_id]["oInteracting"] = {}
                q_list_old_detail[queue_id]["oWaiting"] = {}
                q_list_old_detail[queue_id]["oInteracting"]["conversation"] = []
                q_list_old_detail[queue_id]["oWaiting"]["conversation"] = []

            # make a copy of the json structure.
            q_list_agent_details = q_list_old_detail

            for item in response_json:
                q_list_old_detail[item["queue_id"]][item["metric"]]["conversation"].append(item["contact_id"])
                detail = item["details"]
                if not detail:
                    logger.info("detail is empty")
                    data = {}
                    data['queue_id'] = item["queue_id"]
                    data['conversation_id'] = item["contact_id"]
                    logger.info(f"Update Details: {data}")
                    map_assignment.append(data)

                # q_list_agent_details[item["queue_id"]][item["metric"]]["conversation"].append(item["contact_id"])
                # previous_detail = item["agents"]
                # if not previous_detail:
                #     logger.info("Preview agent is empty")
                #     data = {}
                #     data['queue_id'] = item["queue_id"]
                #     data['conversation_id'] = item["contact_id"]
                #     logger.info(f"Update Details: {data}")
                #     map_assignment_agent.append(data)

            logger.info(f"get_update_contact_details.LENGTH: {len(map_assignment)}")
            with ThreadPoolExecutor(max_workers = 10) as executor:
                for result in executor.map(self.__get_contacts_details, map_assignment):
                    logger.info("get_update_contact_details.END")

            # logger.info(f"get_update_contact_agents.LENGTH: {len(map_assignment_agent)}")
            # with ThreadPoolExecutor(max_workers = 10) as executor:
            #     for result in executor.map(self.__get_previous_agent, map_assignment_agent):
            #         logger.info("get_update_contact_agents.END")
                                
            response_json =self.__get_q_contacts_gc(q_array, q_list_old_detail)
            
            # Need to implement forloop with truncat list with ThreadPoolExecutor.
            q_id = "5c3de963-3b88-46bd-807f-329903f5091a"
            result = self.__get_truncated_contacts_gc(q_id, q_list_old_detail[q_id])

            
            # return response_json['result']   
            return result 
        except Exception as e:
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

    def __get_q_contacts_db(self):
        try:
            logger.info("__get_q_contacts_db.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            response = table.scan()
            logger.info("__get_q_contacts_db: AFTER SCAN")
            # logger.info(response)
            response_json = response['Items']
            response_json_temp = json.dumps(response_json, default=self.__rep_decimal)
            logger.info("__get_q_contacts_db.END")
            return json.loads(response_json_temp) 
        except Exception as e:
            logger.error(f"__get_q_contacts_db.Exception: {e}")
            raise e

    def __get_q_contacts_gc(self, q_array, q_list_old):
        try:
            logger.info("__get_q_contacts_gc.START")
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}",
                "Content-Type": "application/json"
            }
            request_body = self.__get_filter(q_array)
            response = requests.post(self.env["q_query_url"], json=request_body, headers=requestHeaders)
            # logger.info(f"__get_q_contacts_gc.response: {response}")

            if response.status_code == 200:
                logger.info("__get_q_contacts_gc: Got 200 ok to get contacts")
            else:
                logger.info(f"__get_q_contacts_gc.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Genesys access token: { str(response.status_code) } - { response.reason }")
            # logger.info(f"__get_q_contacts_gc.response: {response.json()}")
            result = self.__process_result(response.json(), q_list_old)
            logger.info("__get_q_contacts_gc.END")
            return result               
        except Exception as e:
            logger.error(f"__get_q_contacts_gc.Exception: {e}")
            raise e    

    def __get_truncated_contacts_gc(self, queue_id, q_list_old):
        try:
            logger.info("__get_q__get_truncated_contacts_gc_contacts_gc.START")
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}",
                "Content-Type": "application/json"
            }
            request_body = self.__get_truncat_filter(queue_id)
            response = requests.post(self.env["t_contact_url"], json=request_body, headers=requestHeaders)
            # logger.info(f"__get_truncated_contacts_gc.response: {response}")

            if response.status_code == 200:
                logger.info("__get_truncated_contacts_gc: Got 200 ok to get contacts")
            else:
                logger.info(f"__get_truncated_contacts_gc.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Truncated Contacts: { str(response.status_code) } - { response.reason }")
            # logger.info(f"__get_truncated_contacts_gc.response: {response.json()}")
            result = response

            result = self.__process_truncat_result(response.json(), q_list_old, queue_id)
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
            self.__update_details(response_json)
            logger.info("__get_contacts_details.END")
            return response.json()               
        except Exception as e:
            logger.error(f"__get_contacts_details.Exception: {e}")
            raise e

    def __get_previous_agent(self, data):
        try:
            logger.info("__get_previous_agent.START")
            requestHeaders = {
                "Authorization": f"{ self.secret_token['token_type'] } { self.secret_token['access_token']}"
            }
            p_agent_url_temp = self.env['previous_agents_url']
            p_agent_url = p_agent_url_temp.replace("CONVERSATION_ID", data['conversation_id'])
            response = requests.get(p_agent_url, headers=requestHeaders)
            # logger.info(f"response: {response}")

            if response.status_code == 200:
                logger.info("__get_previous_agent: Got 200 OK for get contacts details.")
            else:
                logger.info(f"__get_previous_agent.Failure: { str(response.status_code) } - { response.reason }")
                raise Exception(f"Failure to get Contact travel details: { str(response.status_code) } - { response.reason }")
            response_json = response.json()
            response_json["queue_id"] = data['queue_id']
            response_json["conversation_id"] = data['conversation_id']
            self.__update_agents(response_json)
            logger.info("__get_previous_agent.END")
            return response.json()               
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

    def __get_truncat_filter(self, queue_id):
        try:
            logger.info("__get_truncat_filter.START")
            filter_json = {}
            filter_json["interval"] = "2022-09-07T00:00:00.000Z/2022-09-15T22:00:00.000Z"
            filter_json["order"] = "desc"
            filter_json["orderBy"] = "conversationStart"

            filter_json["paging"] = {}
            filter_json["paging"]["pageSize"] = 100  
            filter_json["paging"]["pageNumber"] = 1
            
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

    def __process_result(self, result_json, q_list_old):
        try:
            logger.info("__process_result.START")
            epoch_time = int(time.time())
            data_json = []
            qlist_json = {}
            qlist_json['queues'] = []
            qlist_json['timestamp'] = epoch_time
            
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
                        conversation["agents"] = {}
                        conversation["timestamp"] = epoch_time
                        conversation["metric"] = metric
                        data_json.append(conversation)

            # logger.info(f"__process_result.qlist_json: {qlist_json}")
            self.__update_q_list(qlist_json)
            add_del_list = self.__compare_q_list(qlist_json, q_list_old, truncated_json)
            # logger.info(f"__process_result.add_del_list: {add_del_list}")
            result = self.__update_q_table(data_json, add_del_list)
            logger.info(f"__process_result.truncated_json: {truncated_json}")
            logger.info("__process_result.END")
            return {"result": result, "truncat": truncated_json} 
        except Exception as e:
            logger.error(f"__process_result.Exception: {e}")
            raise e   

    def __process_truncat_result(self, result_json, q_list_old, queue_id):
        try:
            logger.info("__process_truncat_result.START")
            logger.info(f"__process_truncat_result.queue_id:{queue_id}")
            epoch_time = int(time.time())
            c_list_json = {}
            c_list_json[queue_id] = {}
            c_list_json[queue_id]["oWaiting"] = {}
            c_list_json[queue_id]["oWaiting"]['conversation'] = []  
            for conversation in result_json["conversations"]:
                con_json = {}
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
                con_json["agents"] = {}
                con_json["timestamp"] = epoch_time
                con_json["metric"] = "oWaiting"
                
                for participant in conversation["participants"]:
                    if participant["purpose"] == "acd":
                        con_json["data"]["participantName"] = participant["participantName"]
                        for session in participant["sessions"]:
                            con_json["data"]["addressFrom"] = session["addressFrom"]
                            con_json["data"]["addressTo"] = session["addressTo"]
                            con_json["data"]["direction"] = session["direction"]
                            con_json["data"]["sessionId"] = session["sessionId"]
                            for metric in session["metrics"]:
                                con_json["data"]["observationDate"] = metric["emitDate"]




                c_list_json[queue_id]["oWaiting"]['conversation'].append(con_json)

            add_del_list = self.__compare_truncat_list(c_list_json, q_list_old, queue_id)
            # # logger.info(f"__process_truncat_result.add_del_list: {add_del_list}")
            # # result = self.__update_q_table(data_json, add_del_list)
            # logger.info(f"__process_truncat_result.truncated_json: {truncated_json}")
            # logger.info("__process_truncat_result.END")
            result_json = {}
            # result_json["Conversation"] = data_json
            # result_json["c_list_json"] = c_list_json
            result_json["add_del_list"] = add_del_list
            
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

    def __compare_q_list(self, new_json, old_json, truncated_json):
        try:
            logger.info("__compare_q_list.START")
            add_qlist = {}
            del_qlist = {}
            # update_qlist = {}
            queues = []
            # logger.debug(f"__compare_q_list.new_json['queues'] {new_json['queues']}")
            for queue_id in new_json['queues']:
                queues.append(queue_id)
                add_qlist[queue_id] = []
                del_qlist[queue_id] = []
                # update_qlist[queue_id] = []
                if queue_id in truncated_json["queues"]:
                    logger.debug(f"__compare_q_list.FOR LOOP CONTINUE {queue_id}")
                    continue
                for conversation_id in new_json[queue_id]['oWaiting']['conversation']:
                    # logger.debug(f"__compare_q_list.conversation_id: {conversation_id}")
                    if old_json == None:
                        if conversation_id not in add_qlist[queue_id]:
                            add_qlist[queue_id].append(conversation_id)
                        logger.info(f"__compare_q_list.add_qlist: {add_qlist[queue_id]}")
                        continue
                    # logger.info(f"__compare_q_list.old_json[queue_id]:{old_json[queue_id]['oWaiting']['conversation']}")
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
                    # for conversation_id in old_json[queue_id]['conversation']:
                    #     if conversation_id not in new_json[queue_id]['conversation']:
                    #         del_qlist[queue_id].append(conversation_id)
                    # Karuna - code change for include interaction emails.
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
            # result["update"] = update_qlist
            logger.info("__compare_q_list.END")
            return result
        except Exception as e:
            logger.error(f"__compare_q_list.Exception: {e}")
            raise e

    def __compare_truncat_list(self, new_json, old_json, queue_id):
        try:
            logger.info("__compare_truncat_list.START")
            add_qlist = {}
            del_qlist = {}

            add_qlist[queue_id] = []
            del_qlist[queue_id] = []

            for conversation_id in new_json['oWaiting']['conversation']:
                if old_json == None:
                    if conversation_id not in add_qlist[queue_id]:
                        add_qlist[queue_id].append(conversation_id)
                    logger.info(f"__compare_truncat_list.add_qlist: {add_qlist[queue_id]}")
                    continue
                # logger.info(f"__compare_truncat_list.old_json[queue_id]:{old_json[queue_id]['oWaiting']['conversation']}")
                if conversation_id not in old_json[queue_id]['oWaiting']['conversation']:
                    if conversation_id not in add_qlist[queue_id]:
                        add_qlist[queue_id].append(conversation_id)

            # # update_qlist = {}
            # queues = []
            # # logger.debug(f"__compare_truncat_list.new_json['queues'] {new_json['queues']}")
            # for queue_id in new_json['queues']:
            #     queues.append(queue_id)
            #     add_qlist[queue_id] = []
            #     del_qlist[queue_id] = []
            #     # update_qlist[queue_id] = []

            #     for conversation_id in new_json[queue_id]['oWaiting']['conversation']:
            #         # logger.debug(f"__compa__compare_truncat_listre_q_list.conversation_id: {conversation_id}")
            #         if old_json == None:
            #             if conversation_id not in add_qlist[queue_id]:
            #                 add_qlist[queue_id].append(conversation_id)
            #             logger.info(f"__compare_truncat_list.add_qlist: {add_qlist[queue_id]}")
            #             continue
            #         # logger.info(f"__compare_truncat_list.old_json[queue_id]:{old_json[queue_id]['oWaiting']['conversation']}")
            #         if conversation_id not in old_json[queue_id]['oWaiting']['conversation']:
            #             if conversation_id not in add_qlist[queue_id]:
            #                 add_qlist[queue_id].append(conversation_id)
            #     for conversation_id in new_json[queue_id]['oInteracting']['conversation']:
            #         if old_json == None:
            #             if conversation_id not in add_qlist[queue_id]:
            #                 add_qlist[queue_id].append(conversation_id)
            #             continue
            #         if conversation_id not in old_json[queue_id]['oInteracting']['conversation']:
            #             if conversation_id not in add_qlist[queue_id]:
            #                 add_qlist[queue_id].append(conversation_id)

            #     if old_json != None:
            #         # for conversation_id in old_json[queue_id]['conversation']:
            #         #     if conversation_id not in new_json[queue_id]['conversation']:
            #         #         del_qlist[queue_id].append(conversation_id)
            #         # Karuna - code change for include interaction emails.
            #         for conversation_id in old_json[queue_id]['oWaiting']['conversation']:
            #             if (conversation_id not in new_json[queue_id]['oWaiting']['conversation']):
            #                 if conversation_id not in del_qlist[queue_id]:
            #                     del_qlist[queue_id].append(conversation_id)
            #         for conversation_id in old_json[queue_id]['oInteracting']['conversation']:
            #             if (conversation_id not in new_json[queue_id]['oInteracting']['conversation']):
            #                  if conversation_id not in del_qlist[queue_id]:
            #                     del_qlist[queue_id].append(conversation_id)
            result = {}
            result["add"] = new_json
            # result["del"] = old_json
            # result["queues"] = queues
            # result["update"] = update_qlist
            logger.info("__compare_truncat_list.END")
            return result
        except Exception as e:
            logger.error(f"__compare_truncat_list.Exception: {e}")
            raise e

    def __update_q_table(self, result_json, add_del_list):
        try:
            logger.info("__update_q_table.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
            map_assignment =[]
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
                    # for conversation_id in add_del_list["update"][queue_id]:
                    #     logger.info(f"Update ITEM: {conversation_id}")
                    #     batch.update_item(
                    #         Key={
                    #             'queue_id': queue_id,
                    #             'contact_id': conversation_id
                    #         },
                    #         UpdateExpression="SET #s_column=:s_value",
                    #         ExpressionAttributeNames={
                    #             "#s_column": "metric"
                    #             },
                    #         ExpressionAttributeValues={
                    #             ':s_value': 'oInteracting',
                    #         }
                    #     )
            with table.batch_writer() as batch:
                for conversation in result_json:
                    queue_id = conversation["queue_id"]
                    if conversation["contact_id"] in add_del_list["add"][queue_id]:
                        logger.info(f"__update_q_table.PUT ITEM: {conversation['contact_id']}")
                        batch.put_item(
                            Item=conversation
                        )
                        data = {}
                        data['queue_id'] = queue_id
                        data['conversation_id'] = conversation["contact_id"]
                        map_assignment.append(data)


            # # Karuna - contact detail will be updated using get_update_contact_details method.
            # # get_update_contact_details -> this method is call every one minute using Amazon EventBridge
            # # So we are commenting the below line.
            # logger.info(f"__update_q_table.LENGTH: {len(map_assignment)}")
            # with ThreadPoolExecutor(max_workers = 10) as executor:
            #     # task = executor.map(self.__get_contacts_details, map_assignment)
            #     for result in executor.map(self.__get_contacts_details, map_assignment):
            #         logger.info("__update_q_table.RESULT")

            result = self.__get_q_contacts_db()
            # return result_json
            logger.info("__update_q_table.END")
            return result
        except Exception as e:
            logger.error(f"__update_q_table.Exception: {e}")
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
    #         logger.info(f"LENGTH: {len(map_assignment)}")
    #         with ThreadPoolExecutor(max_workers = 10) as executor:
    #             # task = executor.map(self.__get_contacts_details, map_assignment)
    #             for result in executor.map(self.__get_contacts_details, map_assignment):
    #                 logger.info("RESULT")

    #         result = self.__get_q_contacts_db()
    #         # return result_json
    #         return result
    #     except Exception as e:
    #         raise e 

    def __update_details(self, result_json):
        try:
            logger.info("__update_details.START")
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
            logger.info("__update_details.END")
            return response
        except Exception as e:
            logger.error(f"__update_details.Exception: {e}")
            raise e        

    def __update_agents(self, result_json):
        try:
            logger.info("__update_details.START")
            table = self.dynamodb.Table(self.env['tbl_contact_details'])
             
            response = table.update_item(
                Key={
                    'queue_id': result_json['queue_id'],
                    'contact_id': result_json['conversation_id'],
                },
                UpdateExpression="SET #s_column=:s_value",
                ExpressionAttributeNames={
                    "#s_column": "agents"
                    },
                ExpressionAttributeValues={
                    ':s_value': result_json,
                }
            ) 
            logger.info("__update_details.END")
            return response
        except Exception as e:
            logger.error(f"__update_details.Exception: {e}")
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

    def get_test(self):
        try:
            logger.info("get_test.START")

            q_list_old = {
                            "oInteracting": {
                                "conversation": []
                            },
                            "oWaiting": {
                                "conversation": [
                                    "03d56a0e-7b41-42d4-8d3d-c37677119f95",
                                    "19f34f83-b5b3-49ac-9f96-44481de40330",
                                    "1a2c7b79-9af4-41fe-a8cb-10caeb40611c",
                                    "1e4e9456-a540-42e0-a054-6b6078e8512f",
                                    "1e660972-fff7-4fd7-b007-3daeabe78d70",
                                    "1e8f51ca-fdf6-4422-b82a-3992999a7a09",
                                    "204835b0-b2a5-4fbb-9698-9513f5ad8e06",
                                    "289ec45f-5816-48ee-bbcf-5a24fa74698f",
                                    "2da46310-1757-4ee9-bd7f-258908f375a5",
                                    "315e71a9-ddc7-4714-85f4-23c088aa8038",
                                    "33c5516b-032b-4d42-840b-da3395f05931",
                                    "399bfc33-9e68-4e0a-9287-eafa622bc879",
                                    "39c23fff-ed0f-4ff6-a6b8-25b2f4e0c0a9",
                                    "3dbbf947-3430-43ac-9cad-1c1a9889f05d",
                                    "49d510db-2ed9-427d-aa49-d19bd36c9767",
                                    "4c1b2afd-b3d6-44d5-9000-f4bdbdf96844",
                                    "4ccee194-c91b-4281-946e-141a02c30acf",
                                    "5279938f-f9c7-4653-87ec-a3e771bf8c69",
                                    "64199c5f-ff08-4f8d-84f0-78b2401312f2",
                                    "6c50249b-69aa-454e-afce-7c32c5eb5f30",
                                    "75110ef1-2eb9-4d46-9914-20eccf09f6cf",
                                    "7cf51a26-3442-4d03-9d7d-cdf416b33536",
                                    "83983744-d19a-49fb-9d93-c3bb5c0a11a6",
                                    "8af8dc9b-3a3c-45f3-8e9b-0db5b0def4e9",
                                    "a62c1586-1cec-4f7e-9a89-c9eebbbb88de",
                                    "b4059c1c-d3cf-43f3-862d-1281afc87cdf",
                                    "b8436ab3-6fc1-4d00-85a8-ccd2793ee1cb",
                                    "bc5e12ad-c97c-41bc-bb5e-1a09ab8c6a84",
                                    "c970dc57-535f-4713-b201-6bd688acb16c",
                                    "ce905a4c-9de6-4075-991b-d52d55bb1e3a",
                                    "e2ac8018-4b54-490d-b0c2-ed1d34ea91c5",
                                    "e6e6c72d-2b6b-4064-8b14-f9c2bad1c637",
                                    "eec8af8f-ff1c-47b8-88b1-b39b0bd5d6b2",
                                    "f1085b9b-d77d-4ecd-a6ec-1817f08ed7e8"
                                ]
                            }
                        }
                    


            response = self.__get_truncated_contacts_gc("5c3de963-3b88-46bd-807f-329903f5091a", q_list_old)
            # response = {"test":"Karuna"}
            logger.info("get_test.END")
            return response
        except Exception as e:
            logger.error(f"get_test.Exception: {e}")
            raise e                