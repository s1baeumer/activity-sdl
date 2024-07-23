#!/usr/bin/python
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta
import yaml
import threading
from time import sleep, time_ns
import os , requests , urllib3, json, uuid
from requests.exceptions import HTTPError

#logging.basicConfig(TimedRotatingFileHandler( '/logs/activity-sdl.log',when='midnight',backupCount=7)],level=logging.DEBUG,format='%(asctime)s  - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
logging.basicConfig(handlers=[ TimedRotatingFileHandler( '/logs/activity-sdl.log',when='midnight',backupCount=7)],level=logging.INFO,format='%(asctime)s  - %(levelname)s - %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
logging.info("=======================================================================")
# TODO SCOPE FILTERING
# TODO LOGROTATION
# TODO PRIORIZATION
# TODO MESSAGE CONSOLIDATION

## 
# CONVERT EVENT DATA TO ACTIVITY SCHEMA
##
def convert_to_schema(d):
    a = activtity_schema['activity']
    e = dict()
    for k1,v1 in d.items():
        if (isinstance(v1, (dict,list))): 
            for k2, v2 in v1.items():
                e[str("activity.data."+k2)] = v2
        else: 
            e[a[k1]] = v1
    return e


##
# READ CONFIG 
## 
logging.info("GLOBAL - trying to load config file")
try:
    with open('conf/config.yml', 'r') as file:
        conf = yaml.safe_load(file)
    logging.info("GLOBAL - sucessfully loaded config file from conf/config.yaml")
except:
    logging.critical("GLOBAL - could not load the config file")

##
# READ ACTIVITY SCHEMA
##
logging.info("GLOBAL - trying to load activity schema file")
try:
    with open('conf/activity_schema.yml', 'r') as file:
        activtity_schema = yaml.safe_load(file)
    logging.info("GLOBAL - sucessfully loaded config file from conf/activity_schema.yaml")
except:
    logging.critical("GLOBAL - could not load the config file")


##
# QUERY FOR ACTIVITIES BETWEEN LAST SUCCESSFUL QUERY AND NOW 
##
def FetchActivity(data):
    # Setting headers for auth
    headers = {'Authorization': 'ApiToken '+data['s1-api'] , 'Content-type': 'application/json'}

    logging.debug(data['s1-name']+" - Try to fetch activity logs for customer from: "+data['s1-url'])

    # Get Activity from now minus interval 
    now = datetime.utcnow()
    before = now-timedelta(seconds=data['interval'])
    t_now = now.strftime("%Y-%m-%dT%H:%M:%S")
    t_before = before.strftime("%Y-%m-%dT%H:%M:%S")
    t_diff = "createdAt__gte="+t_before+"&createdAt__lt="+t_now

    # # SET FILTER FOR ACTIVITY IDS 
    # if (data['activity_groups'][0] != 'all'):
    #     all_activities_filtered = list()
    #     for at in data['activity_groups']:
    #         for sat in global_activity_group_ids[at].split(","):
    #             all_activities_filtered.append(sat)
        
    #     # REMOVE DUPLICATE ENTRIES
    #     all_activities_filtered = list(set(all_activities_filtered))
    #     ActivityFilters = "&activityTypes="+",".join(sorted(all_activities_filtered))
    # else: 
    #     all_activities_filtered = list()
    #     for at in conf['activities']:
    #         for sat in global_activity_group_ids[at].split(","):
    #             all_activities_filtered.append(sat)
    #     # REMOVE DUPLICATE ENTRIES
    #     all_activities_filtered = list(set(all_activities_filtered))
    #     ActivityFilters = "&activityTypes="+",".join(sorted(all_activities_filtered))
    #
    # logging.debug(data['s1-name']+" - Activity filter: "+ActivityFilters)

    # TODO SET FILTER FOR SCOPES

    # INITIALIZE VARIABLES FOR LOOP
    cursor = ""
    activities = list()

    try:
        logging.debug(data['s1-name']+" - Start iteration")
        while cursor != None: 
            # EXECUTE REQUEST TO MGMT FOR ACTIVITIES
            #request_string = data['s1-url']+"/web/api/v2.1/activities?limit=1000&"+t_diff+ActivityFilters+"&cursor="+cursor
            request_string = data['s1-url']+"/web/api/v2.1/activities?limit=1000&"+t_diff+"&cursor="+cursor
            logging.debug(data['s1-name']+" - "+request_string)
            res = json.loads(requests.get(request_string, headers=headers).text)
            logging.debug(data['s1-name']+" - "+json.dumps(res))
            # LOOP THROUGH RESULTS TO ADD TO LIST 
            if (res['data'] != None ): 
                for sa in res['data']:
                    activities.append(sa)
                cursor = res['pagination']['nextCursor']
                logging.info(data['s1-name']+" - Fetched "+str(len(activities))+" activities")
            else:
                logging.error(data['s1-name']+" - A request error occured ("+str(res['errors']['code'])+"): "+str(res['errors']['detail']))

        return activities
    except HTTPError as http_err:
        logging.debug(data['s1-name']+" - "+request_string)
        logging.error(data['s1-name']+" - "+f'HTTP error occurred: {http_err}')
        e = res.json()
        logging.error(data['s1-name']+" - "+"The following error was reported: "+json.dumps(e))
        return False
    except Exception as err:
        logging.debug(data['s1-name']+" - "+request_string)
        logging.error(data['s1-name']+f' - Exception occurred: {err}')
        return False

##
# CALL SINGULARITY DATALAKE API
##
def SendMessageToSDL(activitydata, customerdata):
    try:
        logging.debug(customerdata['s1-name']+" - Start iteration to ingest messages")
        for e in activitydata:
            s_events = []
            logging.debug(e)
            # create timestamp
            t1 = e['createdAt'].split(".")
            ts = str(int(datetime.strptime(t1[0], "%Y-%m-%dT%H:%M:%S").timestamp()))+str(int(t1[1][0:2:1]))
            meta_info={
                "event.time" : ts,
                "dataSource.category": "security",
                "dataSource.vendor": "EvilTwins",
                "dataSource.name": "ActivityLog",
                "event.type": "Activity",
                "site.id" : e['siteId']
            }
            e = convert_to_schema(e)
            e.update(meta_info)
            s_events.append({
                "source" : "ActivityLog",
                "parser" : "json",
                "ts": time_ns(), 
                "sev": 3, 
                "attrs":  e
            })

            # EXECUTE POST TO SDL
            s_data = {
                "token": customerdata['sdl-api'],
                "session" : str(uuid.uuid4()),
                "sessionInfo" : {
                },
                "events": s_events
            }

            logging.debug(customerdata['s1-name']+" - "+customerdata['sdl-url'])
            headers = {'content-type': 'application/json'}
            r = requests.post(customerdata['sdl-url']+"/api/addEvents", data=json.dumps(s_data), headers=headers)
            logging.debug(str(r))
            if r.status_code == 200:
                logging.debug("successfully posted data to SDL")
                logging.debug(customerdata['s1-name']+" - data sent: "+str(json.dumps(s_data)))
                logging.debug(customerdata['s1-name']+" - Response from SDL"+str(r.text))
            else:
                logging.error(r.text)

        logging.info(customerdata['s1-name']+" - sent "+str(len(activitydata))+" activities to SDL")
        return True
    except HTTPError as http_err:
        logging.error(customerdata['s1-name']+" - "+f'HTTP error occurred: {http_err}')
        e = r.json()
        logging.error(customerdata['s1-name']+" - "+"The following error was reported: "+json.dumps(e))
        return False
    except Exception as err:
        logging.error(customerdata['s1-name']+f' - Exception occurred during ingestion api call: {err}')
        return False


##
# MAIN FUNCTION FOR THREADS
##
def ThreadMain(index):

    while True:
        # SETTING START TIME FOR LOOP 
        starttime_interval = datetime.timestamp(datetime.utcnow())                          

        # Query Data from Mgmt
        a = FetchActivity(conf['service'][index]['customer'])
        if a != False and len(a) > 0:
            logging.debug(conf['service'][index]['customer']['s1-name']+" - "+json.dumps(a))
            # call singularity data lake addEvent api
            SendMessageToSDL(a, conf['service'][index]['customer'])

        endtime_interval = datetime.timestamp(datetime.utcnow())  
        # SLEEP
        tdiff = conf['service'][index]['customer']['interval']-(endtime_interval-starttime_interval) 
        if (tdiff < 0): 
            sleep(conf['service'][index]['customer']['interval'])
        else:
            sleep (tdiff)


if __name__ == '__main__':
    threads = list()
    i=0
    logging.info("GLOBAL - Starting to loop through customers")
    for index in range(len(conf['service'])):
        x = threading.Thread(target=ThreadMain, args=(i,))
        threads.append(x)
        x.start()
        logging.debug(conf['service'][index]['customer']['s1-name']+" - thread (id="+str(i)+")started")
        i+=1

    for index, thread in enumerate(threads):
        thread.join()
    logging.info("GLOBAL - program stopped")
