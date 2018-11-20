# NMOS Registry Test

A unittest written for a IS-04 query- and registration-server.

## Usage
Configure connection data to the registry via the ```defines.py``` file.

At least configure:
- ```SERVER_PROTO```: Protocol
- ```SERVER_IP```: IP address 
- ```SERVER_PORT```: Port

Optional modifiable parameters:
- ```VERSIONS```: Choose the versions which you want to test. Currently ```v1.0```, ```v1.1``` and ```v1.2``` are supported
- ```RELAXED_TRAILING_SLASH_POLICY```: ```True``` / ```False``` Only check for correct trailing slash handling where mandatory
- ```REQUEST_SLEEP```: ```True``` / ```False``` if there should be a timeout between consecutive requests
- ```REQUEST_SLEEP_TIME```: If ```REQUEST_SLEEP``` is defined, define how long the timeout should be (s)
- ```MDNS_WAIT_TIME```: Search duration for MDNS announcements (s)
- ```HEARTBEAT_TIMEOUT```: Wait (s) until the servers garbage collection mechanism should have done it's work
- ```WAIT_WS_MSG```: Wait (s) before checking websocket messages after making a change via the REST api
- ```WAIT_WS_OPENING```: Wait (s) before checking websocket messages after establishing a websocket connection
- ```CHECK_OPTIONS_RESPONSE```: ```True``` / ```False``` if the ```OPTIONS``` http method should be checked
- ```CHECK_HEAD_RESPONSE```: ```True``` / ```False``` if the ```HEAD``` http method should be checked
- ```HEAD_COMPARE_HEADERS```: If ```CHECK_HEAD_RESPONSE``` is set, define headers explicitly to be checked (Default: ```["Content-Type", "Content-Length", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Max-Age", "Server"]```) 
- ```CORS_HEADERS```: Choose the CORS headers should be checked (only if ```<KEY>``` is available in header) (Default: ```["Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Max-Age"]```) 

To execute the test, run the ```main.py``` file.

## Requirements
Created for ```python3.6``` with the following external dependencies:
- ```requests```
- ```zeroconf==0.17.5```
- ```netifaces```
- ```websocket-client```
- ```jsonschema```
