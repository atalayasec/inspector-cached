import base64
from flask import request, jsonify
from utils import score_creator

from analysis_manager import get_manager

response_headers = {"Accept": "application/json"}


def json_response(msg, status, error=False):
    return (jsonify({"error": error, "result": msg}), status, response_headers)


def load_from_request(r):
    return r.get_json()


def b64_encode(data):
    return base64.b64encode(data)


def b64_decode(data):
    return base64.b64decode(data)


def r_set_configuration_values():
    '''Receives configuration values and updates internal configuration'''
    if not request.is_json:
        return json_response("only json is accepted", 400, error=True)
    json_data = request.get_json(silent=True)
    if "virustotal_api_key" not in json_data and "cuckoo_username" not in json_data and "cuckoo_password" not in json_data:
        return json_response("must contain at least virustotal_api_key or cuckoo_username and cuckoo_password", 400, error=True)
    manager = get_manager()
    api_key_updated = credentials_updated = False
    if "virustotal_api_key" in json_data:
        api_key_updated = True
        manager.update_api_key("virustotal", json_data.get("virustotal_api_key"))
    if "cuckoo_username" in json_data or "cuckoo_password" in json_data:
        credentials_updated = True
        manager.update_credentials("cuckoo", json_data.get("cuckoo_username"), json_data.get("cuckoo_password"))
    return json_response(
        "api key updated {} credentials updated {}".format(api_key_updated, credentials_updated),
        200
    )

def r_get_configured_analysers():
    manager = get_manager()
    return json_response(
        manager.usable_analysers_names(),
        200
    )

def r_passthrough_url(url):
    v = get_manager().get_analyser("virustotal")
    if not v:
        raise ValueError("no virustotal analysers found")
    data = v.view("url", url)
    resp_code = data.get('response_code')
    if resp_code != 1:
        return json_response("unknown", 200)
    else:
        n_found = data.get("total")
        scans = data.get("scans", [])
        positives = sum([x.get("detected") for x in scans.values()])
        score = (positives * 100) / n_found
        return json_response(score_creator("virustotal",
                                 score,
                                 {
                                    "total": data.get("total"),
                                    "positives": data.get("positives"),
                                     "scan_date": data.get("scan_date")
                                 }),
                             200)

def r_passthrough_hash(hash):
    v = get_manager().get_analyser("virustotal")
    if not v:
        raise ValueError("no virustotal analysers found")
    data = v.view("file", hash)
    resp_code = data.get('response_code')
    if resp_code != 1:
        return json_response("unknown", 200)
    else:
        n_found = data.get("total")
        scans = data.get("scans", [])
        positives = sum([x.get("detected") for x in scans.values()])
        score = (positives * 100) / n_found
        return json_response(score_creator("virustotal",
                                score,
                                 {
                                    "total": data.get("total"),
                                    "positives": data.get("positives"),
                                     "scan_date": data.get("scan_date")
                                 }),
                             200)


def r_new_from_hash(hash):
    '''Receives a hash and tests only on hash aware analysers'''
    task = get_manager().new_file(None, from_hash=hash)
    return json_response({"id": task.id}, 201)


def r_new_file():
    '''Receives a json struct with the base64 encoded file data as the filedata key value
    and an optional filename. Returns the internal id of the task'''
    filedata_key = "filedata"
    filename_key = "filename"
    if not request.is_json:
        return json_response("only json is accepted", 400, error=True)
    json_data = request.get_json(silent=True)

    filename = json_data.get(filename_key)
    if not json_data:
        return json_response("no request data provided", 400, error=True)
    if filedata_key not in json_data:
        return json_response("must provide filedata", 400, error=True)
    b_filedata = json_data.get(filedata_key)
    filedata = b64_decode(b_filedata)
    task = get_manager().new_file(filedata, filename=filename)
    return json_response({"id": task.id}, 201)


def r_task_status(id):
    """Receives the id of the task for which to fetch the latest view of the
    available results"""
    manager = get_manager()
    task_desc = manager.view_task(id)
    if not task_desc:
        return json_response(
            "task with id {} not found".format(id), 404, error=True)
    return json_response(task_desc, 200)
