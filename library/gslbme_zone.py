#!/usr/bin/python

DOCUMENTATION = '''
---
module: gslbme_zone
short_description: Automates GSLB.me authoritative zones
'''

EXAMPLES = '''
- name: Create zone
    gslbme_zone:
        gslbme_username: "your GSLB.me username"
        gslbme_password: "your GSLB.me API password"
        zonename: "the.zone.name.tld"
        enabled: true|false
        vanitydns: true|false
        contactemail: "the DNS zone postmaster"
        ttl: the-zone-ttl
        state: present|absent
    register: output
- name: Dumps output
    debug:
    msg: '{{ output }}'
  
- name: Create zone using with_items
    gslbme_zone: zonename={{ item.zonename }} enabled={{ item.enabled }} vanitydns={{ item.vanitydns }} contactemail={{ item.contactemail }} ttl={{ item.ttl }} state={{ item.state }} gslbme_username={{ your GSLB.me usenrame }} gslbme_password={{ Your GSLB.me API password }}
    with_items:
        - { zonename: 'zone1.com', enabled: true, vanitydns: false, contactemail: admin@zone1.com, ttl: 3600, state: present }
        - { zonename: 'zone2.com', enabled: false, vanitydns: true, contactemail: admin@zone2.com, ttl: 7200, state: present }
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
def gslbme_create_or_update_zone(data):

    username = data['gslbme_username']
    password = data['gslbme_password']
    zonename = data['zonename']
    
    enabled = data['enabled']
    if enabled == None:
        enabled = True
        
    vanitydns = data['vanitydns']
    if vanitydns == None:
        vanitydns = False
    
    contactemail = data['contactemail']
    if contactemail == None:
        contactemail = "postmaster@"+zonename
        
    ttl = data['ttl']
    if ttl == None:
        ttl = 3600
    
    del data['state']
    
    has_failed, http_code_zone_exists, result = restCall(username=username, password=password, url="/zone/" + zonename, method="GET", headers={'Content-Type':'application/json'}, validate_certs=False)

    if http_code_zone_exists == 200:
        payload = {"contactemail":contactemail, "active":enabled, "ttl":ttl, "vanitydns":vanitydns}
        has_failed, http_code, result = restCall(username=username, password=password, url="/zone/" + zonename, method="PUT", headers={'Content-Type':'application/json'}, validate_certs=False, payload=payload)
    else:
        payload = {"name":zonename, "contactemail":contactemail, "active":enabled, "ttl":ttl, "vanitydns":vanitydns}
        has_failed, http_code, result = restCall(username=username, password=password, url="/zone", method="POST", headers={'Content-Type':'application/json'}, validate_certs=False, payload=payload)    

    meta = {'status': http_code, 'response': result}

    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta

# Returns is_error, has_changed, result
def gslbme_delete_zone(data=None):
    username = data['gslbme_username']
    password = data['gslbme_password']
    zonename = data['zonename']
    
    del data['state']
    
    has_failed, http_code, result = restCall(username=username, password=password, url="/zone/" + zonename, method="DELETE", headers={'Content-Type':'application/json'}, validate_certs=False)

    meta = {'status': http_code, 'response': result}
    
    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta

    
def main():
    
    fields = {
        "gslbme_username": {"required": True, "type": "str" },
        "gslbme_password": {"required": True, "type": "str", "no_log": True },
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": "str"
        },
        "zonename": { "required": True },
        "enabled": { "required": False, "type": "bool" },
        "vanitydns": { "required": False, "type": "bool" },
        "contactemail": { "required": False, "type": "str" },
        "ttl": { "required": False, "type": "int" }
    }
    
    choice_map = {
      "present": gslbme_create_or_update_zone,
      "absent": gslbme_delete_zone 
    }
    
    module = AnsibleModule(argument_spec=fields)

    is_error, has_changed, result = choice_map.get(
        module.params['state'])(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error handling zone", meta=result)


if __name__ == '__main__':
    main()
