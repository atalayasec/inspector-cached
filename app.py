from flask import Flask
from routes import r_new_file, r_task_status, r_set_configuration_values, r_passthrough_hash, r_passthrough_url, r_get_configured_analysers

CONFIGURATION_FILE = "config"

app = Flask("inspector-cached")
app.config.from_object(CONFIGURATION_FILE)

if app.config["DEBUG"]:
    app.add_url_rule("/debug", "do_debug", lambda: 1/0, methods=["GET"])

app.add_url_rule("/vt/hash/<hash>", "passthrough_hash", r_passthrough_hash, methods=["GET"])
app.add_url_rule("/vt/url/<path:url>", "passthrough_url", r_passthrough_url, methods=["GET"])
app.add_url_rule("/new/file", "new_file", r_new_file, methods=["POST"])
app.add_url_rule("/credentials", "update_credentials", r_set_configuration_values, methods=["POST"])
app.add_url_rule("/credentials", "get_credentials", r_get_configured_analysers, methods=["GET"])
app.add_url_rule(
    "/task/<int:id>", "task_status", r_task_status, methods=["GET"])
