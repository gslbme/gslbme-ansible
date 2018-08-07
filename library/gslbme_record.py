#!/usr/bin/python

DOCUMENTATION = '''
---
module: gslbme_record
short_description: Automates GSLB.me authoritative zones records
'''

EXAMPLES = '''
- name: GSLB.me Ansible orchestration
  hosts: localhost
  
  vars:

  tasks:
  
    - name: Create records
      gslbme_record:
        gslbme_username: "{{ gslbme_username }}"
        gslbme_password: "{{ gslbme_password }}"
        zonename: "the.zone.name.tld"
        name: 'recordname'
        type: 'RECORDTYPE'
        value: 'record value'
        ttl: 'the-record-ttl'
        state: present
      register: output
    - name: Dumps output
      debug:
        msg: '{{ output }}'
        
    - name: Create records using with_items
      gslbme_record: gslbme_username={{ gslbme_username }} gslbme_password={{ gslbme_password }} zonename={{ the.zone.name.tld }}  name={{ item.name }} type={{ item.type }} value={{ item.value }} ttl={{ item.ttl }} state={{ item.state }}
      with_items:
        - { name: 'record1', type: 'A', value: '212.0.0.1', ttl: '600', state: present }
        - { name: 'record2', type: 'A', value: '212.0.0.2', ttl: '600', state: present }
        - { name: 'record3', type: 'A', value: '212.0.0.3', ttl: '600', state: present }
        - { name: 'record4', type: 'A', value: '212.0.0.4', ttl: '600', state: present }
        - { name: 'record5', type: 'A', value: '212.0.0.5', ttl: '600', state: present }
      register: output
    - name: Dumps output
      debug:
        msg: '{{ output }}'
'''

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
import requests
import json
import urllib
from asn1crypto._ffi import null

api_url = "https://api.gslb.me/2.0"


# Returns has_failed, http_code, json
def restCall(username, password, url, method, headers, validate_certs, payload=null()):

    try:
        if payload == null():
            resp = open_url(url=api_url + url, method=method, headers=headers, validate_certs=False, url_username=username, url_password=password, force_basic_auth=True)
        else:
            resp = open_url(url=api_url + url, method=method, headers=headers, validate_certs=False, data=json.dumps(payload), url_username=username, url_password=password, force_basic_auth=True)

        resp_read = resp.read()
        resp_json = json.loads(resp_read.decode())
        
        return False, 200, resp_json
    except urllib_error.HTTPError as httpError:
        status_code = int(getattr(httpError, 'code', -1))

        if status_code == 401:
            return True, status_code, json.loads('{"message":"badauth"}')
        else:
            return True, status_code, httpError.read().decode()

# Returns is_error, has_changed, result
# GET https://api.gslb.me/2.0/record/{{zone_name}} 
def gslbme_get_records(username,password,zonename):
    
    has_failed, http_code, result = restCall(username=username, password=password, url="/record/" + zonename, method="GET", headers={'Content-Type':'application/json'}, validate_certs=False)

    meta = {'status': http_code, 'response': result}
    
    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta
    
# Returns is_error, has_changed, result
# PUT https://api.gslb.me/2.0/record/{{zone_name}} 
#{
#   "records": [
#		{
#        	"id": "7555",
#        	"name": "@",
#            "readonly": "false",
#            "ttl": "30",
#            "type": "SSHFP",
#            "value": "4 2 9db8c309c9a27f93e2a096aec7771f7a4d0b6f5edddf520db2728ceff0c89d05"
#        }
#	]
#}
def gslbme_update_record(username,password,zonename,recordid,recordname,recordtype,recordvalue,recordttl):
    
    payload = {"records": [ {"id":recordid,"name":recordname,"type":recordtype,"value":recordvalue,"ttl":recordttl,"readonly":False} ] }
    
    has_failed, http_code, result = restCall(username=username, password=password, url="/record/" + zonename, method="PUT", headers={'Content-Type':'application/json'}, validate_certs=False, payload=payload)

    meta = {'status': http_code, 'response': result}
    
    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta
    
# Returns is_error, has_changed, result
# DELETE https://api.gslb.me/2.0/record/{{zone_name}} 
#{
#   "records": [
#		{ "id": "7554" },
#		{ "id": "7555" }
#	]
#}
def gslbme_delete_record(username,password,zonename,recordid):

    payload = {"records": [ {"id":recordid} ] }
    
    has_failed, http_code, result = restCall(username=username, password=password, url="/record/" + zonename, method="DELETE", headers={'Content-Type':'application/json'}, validate_certs=False, payload=payload)

    meta = {'status': http_code, 'response': result}
    
    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta
    
# Returns is_error, has_changed, result
# POST https://api.gslb.me/2.0/record/{{zone_name}} 
#{
#   "records": [
#        {
#            "name":"dummyrecord",
#            "type":"A",
#            "value":"11.22.33.44",
#            "ttl":"60"
#        }
#    ]s
#}
def gslbme_create_record(username,password,zonename,recordname,recordtype,recordvalue,recordttl):

    payload = {"records": [ {"name":recordname,"type":recordtype,"value":recordvalue,"ttl":recordttl} ] }
    
    has_failed, http_code, result = restCall(username=username, password=password, url="/record/" + zonename, method="POST", headers={'Content-Type':'application/json'}, validate_certs=False, payload=payload)

    meta = {'status': http_code, 'response': result}
    
    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta

# Returns is_error, has_changed, result
# Parameters are username, password, zonename, recordname, recordtype, recordvalue, recordttl, state
def gslbme_record(data=None):
    username = data['gslbme_username']
    password = data['gslbme_password']
    zonename = data['zonename']
    recordname = data['name']
    recordtype = data['type']
    recordvalue = data['value']
    recordttl = data['ttl']
    state = data['state']
     
    has_failed, http_code, result = gslbme_get_records(username=username,password=password,zonename=zonename)
    
    recordFound = False
    
    for record in result['response']['rrset']:
        
        if recordFound == False:
            
            if record['name'] == recordname:
                recordFound = True
                recordId=record['id']

                if record['readonly'] == "false":
                    if state == 'present':
                        has_failed, http_code, result = gslbme_update_record(username=username,password=password,zonename=zonename,recordid=recordId,recordname=recordname,recordtype=recordtype,recordvalue=recordvalue,recordttl=recordttl)
                    else:
                        has_failed, http_code, result = gslbme_delete_record(username=username,password=password,zonename=zonename,recordid=recordId)
    
    if recordFound == False:
        has_failed, http_code, result = gslbme_create_record(username=username,password=password,zonename=zonename,recordname=recordname,recordtype=recordtype,recordvalue=recordvalue,recordttl=recordttl)

    meta = {'status': http_code, 'response': result}
    
    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta

# Main
def main():
    
    fields = {
        "gslbme_username": {"required": True, "type": "str" },
        "gslbme_password": {"required": True, "type": "str", "no_log": True },
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": "str"
        },
        "zonename": { "required": True, "type": "str" },
        "name" : { "required": True, "type": "str" },
        "type" : { "required": True, "type": "str" },
        "value" : { "required": True, "type": "str" },
        "ttl" : { "required": True, "type": "int" }
    }
    
#    choice_map = {
#      "present": gslbme_create_record,
#      "absent": gslbme_delete_record 
#    }
    
    module = AnsibleModule(argument_spec=fields)

#    is_error, has_changed, result = choice_map.get(
#        module.params['state'])(module.params)

    is_error, has_changed, result = gslbme_record(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error handling records", meta=result)


if __name__ == '__main__':
    main()
