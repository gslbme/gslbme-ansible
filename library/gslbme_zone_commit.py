#!/usr/bin/python

# https://blog.toast38coza.me/custom-ansible-module-hello-world/

DOCUMENTATION = '''
---
module: gslbme_zone
short_description: Automates GSLB.me authoritative zones
'''

EXAMPLES = '''
- name: Create a github Repo
  github_repo:
    github_auth_key: "..."
    name: "Hello-World"
    description: "This is your first repository"
    private: yes
    has_issues: no
    has_wiki: no
    has_downloads: no
  register: result
- name: Delete that repo 
  github_repo:
    github_auth_key: "..."
    name: "Hello-World"
    state: absent
  register: result
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
def gslbme_commit_zone(data):

    username = data['gslbme_username']
    password = data['gslbme_password']
    zonename = data['zonename']
        
    has_failed, http_code, result = restCall(username=username, password=password, url="/commit/zone/" + zonename, method="POST", headers={'Content-Type':'application/json'}, validate_certs=False)

    meta = {'status': http_code, 'response': result}

    if has_failed == False:
        return False, True, meta
    else:
        return True, False, meta
    
def main():
    
    fields = {
        "gslbme_username": {"required": True, "type": "str" },
        "gslbme_password": {"required": True, "type": "str", "no_log": True },
        "zonename": { "required": True }
    }
    
    module = AnsibleModule(argument_spec=fields)

    is_error, has_changed, result = gslbme_commit_zone(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error handling zone", meta=result)


if __name__ == '__main__':
    main()
