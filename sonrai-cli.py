#!/usr/local/bin/python3
# This utility is a sample script that provides users with the ability to
# query the control frameworks api "PolicyEvalLogs", retrieve the policy list & affected items
# and prints it out to the user.   It also queries the "ControlPolicies" endpoint to get the
# list of policies and there titles, and adds the titles to the PolicyEvalLogs output.

# For more information on the GraphQL query format, open the
# search UI at https://crc.sonraisecurity.com/, select "Search" then click "Advanced Search".
# In the Advanced Search area, documentation is available to help build your searches.

# In addition, you can also choose to create a saved search with all the filters you wish,
# and then query that search from the script using the "ExecuteSavedQuery" function.

# Dependencies:
# This script requires Python 3, as well as the requests and pyjwt libraries.
# The libraries can be installed by running:
#   pip3 install requests pyjwt
#   (OR)
#   pip3 install -r requirements.txt

# Environment Variables:
# SONRAI_API_SERVER:  GraphQL server address, typically set to "organization.sonraisecurity.com"
# SONRAI_API_TOKEN:   Authentication token for the GraphQL server
# SONRAI_API_TOKENSTORE: Directory in which to store the refreshed auth token
# SONRAI_API_TOKENFILE:  Filename to use to store the refreshed auth token
# SONRAI_DEBUG:       Set to True if you would like debugging messages



import sys, logging
import os
import time
import json
import requests
import jwt
from os import path




#################### def ####################
def SonraiGraphQLQuery(varServer,varQuery,varHeaders):
    myResponse=requests.post(varServer, data=varQuery, headers=varHeaders)
    if myResponse.status_code == 401:
        logging.info("*** Token Authentication failed ***")
        logging.info("token: "+TOKEN)
        logging.info("Token has probably expired, you need to get")
        logging.info("a new one from your web browser session.")
        print ("token expired")
        sys.exit(4)
    myResponse=myResponse.json()
    return myResponse
##  end SonraiGraphQLQuery



#################### def ####################
def storeToken(token):

    logging.debug("# token: storing updated token")
    if not (os.path.exists(TOKENSTORE)):
        os.mkdir(TOKENSTORE)
    with open(os.path.join(TOKENSTORE,TOKENFILE),"w") as tokendest:
        tokendest.write(token)
        tokendest.close()
## end storeToken


#################### def ####################
def UpdateToken(currentToken):
    # check for token in tokenstore.
    tokenCheck=path.exists(os.path.join(TOKENSTORE,TOKENFILE))
    if tokenCheck is False:
        useToken=currentToken
        storeToken(useToken)
        return useToken

    elif tokenCheck is True:
        with open(os.path.join(TOKENSTORE,TOKENFILE),"r") as tokensource:
            token_fromfile = tokensource.read().replace('\n','')
            tokensource.close()

            if len(token_fromfile) < 15:
                logging.debug("# token: using environment token") 
                useToken=currentToken
            else:
                useToken=token_fromfile
                logging.debug("# token: using file token")
            
        # decode & see if token is near expiration
        token_expiry = jwt.decode(useToken,verify=False).get('exp',0)
        current_time = time.time()
        remaining = token_expiry - current_time
        logging.debug("expiry:"+str(token_expiry) + " || current: "+str(current_time) + " || remaining: "+str(remaining))

        # if so, refresh token.  api endpoint will simply return same token if it does not need a refresh (time left < 1/2 token valid time)
        if remaining < 43200:
            logging.debug("# token: near expiry ("+str(int(remaining))+"s), updating")
            # query - get ControlPolicy names & SRNs
            CDC_HEADERS = {"authorization": "Bearer "+useToken, "Content-type": "application/json"}
            CRC_COMMAND = "query integration_renewApiToken { renewApiToken { token, expiry}}"
            POST_FIELDS = {"query": CRC_COMMAND, "variables": "{}"}
            POST_FIELDS = json.dumps(POST_FIELDS)

            NewTokenJson=SonraiGraphQLQuery(URL,POST_FIELDS,CDC_HEADERS)

            newToken=NewTokenJson['data']['renewApiToken']['token']
            logging.debug("# token: storing updated token")
            storeToken(newToken)

        else:
            logging.debug("# token: current token valid, saving ")
            storeToken(useToken)

    return useToken
    # end elif


## end UpdateToken

################### end def ####################


SERVER = os.environ.get("SONRAI_API_SERVER",None)
DEBUG = os.environ.get("SONRAI_DEBUG",False)
TOKEN = os.environ.get("SONRAI_API_TOKEN",None)
TOKENSTORE = os.environ.get("SONRAI_API_TOKENSTORE","/tmp/sonrai")
TOKENFILE = os.environ.get("SONRAI_API_TOKENFILE","token")

if DEBUG in ('True','true','t'):
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)


# print("Debug: "+str(DEBUG))

# if SERVER is None or TOKEN is None:
if SERVER is None:
    print("")
    print(" Usage:  ")
    print(" Set environment variables for:")
    print("    SONRAI_API_SERVER: Sonrai GraphQL server")
    print("    SONRAI_API_TOKEN: Sonrai API auth token")
    print("    SONRAI_API_TOKENSTORE: Directory for the refreshed auth token")
    print("    SONRAI_API_TOKENFILE: Filename for the refreshed auth token")
    print("    SONRAI_DEBUG: True, if desired")
    print("")
    print(" and then run ")
    print(" ./sonraicrc-api.py ")
    print("")
    exit()





# URL: organization graphql server,  https://[orgname].sonraisecurity.com/graphql
URL = "https://"+SERVER+"/graphql"

CurrentToken=str(UpdateToken(TOKEN))
logging.debug(str(CurrentToken))


# authentication headers
CDC_HEADERS = {"authorization": "Bearer "+CurrentToken, "Content-type": "application/json"}


# Sample Query - get ControlPolicy names & SRNs
# CRC_COMMAND = "query API_getPolicies { ControlPolicies { items (limit: -1) {title,description,srn }}}"
# POST_FIELDS = {"query": CRC_COMMAND, "variables": "{}"}
# POST_FIELDS = json.dumps(POST_FIELDS)
# MyPolicies=SonraiGraphQLQuery(URL,POST_FIELDS,CDC_HEADERS)

# MyPoliciesHash = {}
# for i in MyPolicies['data']['ControlPolicies']['items']:
#    MyPoliciesHash[i['srn']] = i['title']

# Sample Query - run ui search "Identity - Users (without MFA)"
# CRC_COMMAND = "query RunQuery { ExecuteSavedQuery { Query (name: \"Identity - Users (without MFA)\") }} "
CRC_COMMAND = "query RunQuery { ExecuteSavedQuery { Query (name: \"ECorp - Activity - Modifications to Andrew\") }} "
POST_FIELDS = {"query": CRC_COMMAND, "variables": "{}"}
POST_FIELDS = json.dumps(POST_FIELDS)
cdc_response=SonraiGraphQLQuery(URL,POST_FIELDS,CDC_HEADERS)


# Query - get alerts
# CRC_COMMAND = "query API_getAlerts { PolicyEvalLogs ( where: { collapse: true}) { items { id, policyId,time,count,pass,srnList,alertingLevel}}}"
# POST_FIELDS = {"query": CRC_COMMAND, "variables": "{}"}
# POST_FIELDS = json.dumps(POST_FIELDS)
# cdc_response=SonraiGraphQLQuery(URL,POST_FIELDS,CDC_HEADERS)




print(json.dumps(cdc_response['data'], indent=4, sort_keys=True))
sys.exit(0)
