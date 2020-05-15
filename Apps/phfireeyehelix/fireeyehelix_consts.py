FIREEYEHELIX_CONN_TEST = '/helix/id/{helix_id}/api/v3/alerts//fields'
FIREEYEHELIX_CEF_MAPPING = {
    "accountname": {"cef_name": "accountname", "cef_contains": ["user name"]},
    "agenthostname": {
        "cef_name": "agenthostname",
        "cef_contains": ["host name"]
    },
    "agentip": {"cef_name": "agentip", "cef_contains": ["ip"]},
    "callingsrcip": {"cef_name": "callingsrcip", "cef_contains": ["ip"]},
    "callingusername": {
        "cef_name": "callingusername",
        "cef_contains": ["user name"]
    },
    "devicename": {"cef_name": "devicename", "cef_contains": ["host name"]},
    "domain": {"cef_name": "domain", "cef_contains": ["domain"]},
    "dstdomain": {"cef_name": "dstdomain", "cef_contains": ["domain"]},
    "dsthost": {"cef_name": "dsthost", "cef_contains": ["host name"]},
    "dstipv4": {"cef_name": "dstipv4", "cef_contains": ["ip"]},
    "dstmac": {"cef_name": "dstmac", "cef_contains": ["mac address"]},
    "dstport": {"cef_name": "dstport", "cef_contains": ["port"]},
    "filename": {"cef_name": "filename", "cef_contains": ["file name"]},
    "filepath": {"cef_name": "filepath", "cef_contains": ["file path"]},
    "hash": {"cef_name": "hash", "cef_contains": ["hash"]},
    "hostname": {"cef_name": "hostname", "cef_contains": ["host name"]},
    "mailfrom": {"cef_name": "mailfrom", "cef_contains": ["email"]},
    "md5": {"cef_name": "md5", "cef_contains": ["md5"]},
    "pid": {"cef_name": "pid", "cef_contains": ["pid"]},
    "ppid": {"cef_name": "ppid", "cef_contains": ["pid"]},
    "pprocess": {"cef_name": "pprocess", "cef_contains": ["process name"]},
    "process": {"cef_name": "process", "cef_contains": ["process name"]},
    "rcptto": {"cef_name": "rcptto", "cef_contains": ["email"]},
    "sha1": {"cef_name": "sha1", "cef_contains": ["sha1"]},
    "sha256": {"cef_name": "sha256", "cef_contains": ["sha256"]},
    "sha512": {"cef_name": "sha512", "cef_contains": ["hash"]},
    "srcdomain": {"cef_name": "srcdomain", "cef_contains": ["domain"]},
    "srchost": {"cef_name": "srchost", "cef_contains": ["host name"]},
    "srcipv4": {"cef_name": "srcipv4", "cef_contains": ["ip"]},
    "srcipv6": {"cef_name": "srcipv6", "cef_contains": ["ip"]},
    "srcmac": {"cef_name": "srcmac", "cef_contains": ["mac address"]},
    "srcport": {"cef_name": "srcport", "cef_contains": ["port"]},
    "targetusername": {
        "cef_name": "targetusername",
        "cef_contains": ["user name"]
    },
    "to": {"cef_name": "to", "cef_contains": ["email"]},
    "uri": {"cef_name": "uri", "cef_contains": ["url"]},
    "url": {"cef_name": "url", "cef_contains": ["url"]},
    "username": {"cef_name": "username", "cef_contains": ["user name"]},
    "xfwdforip": {"cef_name": "xfwdforip", "cef_contains": ["ip"]}
}
