import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

load_dotenv()
app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATE_FILE = BASE_DIR / "dashboard_state.json"

AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
AWS_PROFILE = os.getenv("AWS_PROFILE", "default").strip() or "default"
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "").strip()
LAMBDA_FUNCTION_NAME = os.getenv("LAMBDA_FUNCTION_NAME", "").strip()
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "").strip()
IOT_ENDPOINT = os.getenv("IOT_ENDPOINT", "").strip()
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "security/alert").strip()
# Keep false if the Lambda already publishes to IoT Core. Enable only if the
# dashboard should publish and your Lambda does not already do so.
DASHBOARD_PUBLISH_IOT = os.getenv("DASHBOARD_PUBLISH_IOT", "false").lower() == "true"
# Demo mode lets the dashboard UI run without AWS credentials. Demo results are simulated, not real AWS checks.
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"

_session = None



def aws_session():
    global _session
    if _session is None:
        _session = boto3.Session(region_name=AWS_REGION)
    return _session


def client(service):
    return aws_session().client(service, region_name=AWS_REGION)


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def pretty_time(value):
    if not value:
        return "Not checked"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%d %b %Y, %I:%M:%S %p")
    except (ValueError, TypeError):
        return str(value)


def read_state():
    if not STATE_FILE.exists():
        return {"latest": None, "events": []}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("State file must contain a JSON object.")
        data.setdefault("latest", None)
        data.setdefault("events", [])
        return data
    except (OSError, json.JSONDecodeError, ValueError):
        return {"latest": None, "events": [], "state_warning": "Local dashboard history could not be read."}


def write_state(state):
    # Atomic replace helps avoid a partially-written JSON file.
    fd, temp_name = tempfile.mkstemp(prefix="dashboard_state_", suffix=".json", dir=BASE_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
        os.replace(temp_name, STATE_FILE)
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)


def add_event(event, status, source, detail=""):
    state = read_state()
    item = {
        "time": now_iso(),
        "event": event,
        "status": status,
        "source": source,
        "detail": str(detail)[:500],
    }
    state["events"].insert(0, item)
    state["events"] = state["events"][:100]
    write_state(state)


def error_text(exc):
    if isinstance(exc, NoCredentialsError):
        return "AWS credentials were not found. Configure an AWS CLI profile or environment credentials."
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "AWS error")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return f"AWS permission denied ({code}). Check the IAM permissions in README.md. {message}"
        if code in ("ResourceNotFoundException", "ResourceNotFound", "NoSuchBucket"):
            return f"AWS resource was not found ({code}). Check the configured resource name/ARN. {message}"
        return f"{code}: {message}"
    if isinstance(exc, BotoCoreError):
        return f"AWS SDK/network error: {exc}"
    return str(exc)


def extract_lambda_result(payload_bytes):
    """Parse common Lambda response shapes without making up a SAFE/ALERT value."""
    raw = payload_bytes.decode("utf-8", errors="replace").strip()
    if not raw:
        raise ValueError("Lambda returned an empty payload.")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        upper = raw.upper()
        if upper in ("SAFE", "ALERT"):
            return {"status": upper, "message": "Status returned directly by Lambda.", "condition": ""}
        raise ValueError("Lambda response was not valid JSON or a plain SAFE/ALERT value.")

    # API Gateway-style Lambda results sometimes wrap the JSON in body.
    if isinstance(data, dict) and "body" in data:
        body = data["body"]
        if isinstance(body, str):
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                if body.strip().upper() in ("SAFE", "ALERT"):
                    data = {"status": body.strip().upper()}
        elif isinstance(body, dict):
            data = body

    def search(obj):
        if isinstance(obj, dict):
            for key in ("status", "security_status", "result", "securityResult", "state"):
                value = obj.get(key)
                if isinstance(value, str) and value.strip().upper() in ("SAFE", "ALERT"):
                    return value.strip().upper()
            for value in obj.values():
                found = search(value)
                if found:
                    return found
        elif isinstance(obj, list):
            for value in obj:
                found = search(value)
                if found:
                    return found
        elif isinstance(obj, str):
            if obj.strip().upper() in ("SAFE", "ALERT"):
                return obj.strip().upper()
            try:
                return search(json.loads(obj))
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    status = search(data)
    if not status:
        raise ValueError(
            "Lambda ran, but its response did not contain a SAFE or ALERT status. "
            "Update the Lambda response to return JSON such as "
            "{'status':'SAFE','message':'...','condition':'...'}."
        )

    message = ""
    condition = ""
    if isinstance(data, dict):
        message = str(data.get("message") or data.get("detail") or data.get("reason") or "")
        condition = str(data.get("condition") or data.get("check") or data.get("security_condition") or "")
    return {"status": status, "message": message, "condition": condition, "raw": data}


def get_s3_info():
    if not S3_BUCKET_NAME:
        return {"status": "Not configured", "bucket": "Not configured", "region": AWS_REGION,
                "public_access_block": "Not checked", "error": "Set S3_BUCKET_NAME in .env."}
    try:
        s3 = client("s3")
        s3.head_bucket(Bucket=S3_BUCKET_NAME)
        location = s3.get_bucket_location(Bucket=S3_BUCKET_NAME).get("LocationConstraint")
        bucket_region = location or "us-east-1"
        try:
            config = s3.get_public_access_block(Bucket=S3_BUCKET_NAME)["PublicAccessBlockConfiguration"]
            all_enabled = all(bool(config.get(k)) for k in (
                "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
            ))
            pab = "All four enabled" if all_enabled else "One or more settings disabled"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            pab = "Not configured / not readable" if code in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied") else error_text(exc)
        return {"status": "Reachable", "bucket": S3_BUCKET_NAME, "region": bucket_region,
                "public_access_block": pab, "error": ""}
    except Exception as exc:
        return {"status": "Error", "bucket": S3_BUCKET_NAME, "region": AWS_REGION,
                "public_access_block": "Not checked", "error": error_text(exc)}


def get_service_status():
    services = []
    # Each label reflects what was actually checked, not a claim of end-to-end health.
    if S3_BUCKET_NAME:
        s3 = get_s3_info()
        services.append({"name": "Amazon S3", "status": s3["status"], "detail": s3.get("error") or s3.get("bucket", "")})
    else:
        services.append({"name": "Amazon S3", "status": "Not configured", "detail": "Set S3_BUCKET_NAME."})

    if LAMBDA_FUNCTION_NAME:
        try:
            cfg = client("lambda").get_function_configuration(FunctionName=LAMBDA_FUNCTION_NAME)
            state = cfg.get("State", "Unknown")
            services.append({"name": "AWS Lambda", "status": state, "detail": f"Function: {LAMBDA_FUNCTION_NAME}"})
        except Exception as exc:
            services.append({"name": "AWS Lambda", "status": "Error", "detail": error_text(exc)})
    else:
        services.append({"name": "AWS Lambda", "status": "Not configured", "detail": "Set LAMBDA_FUNCTION_NAME."})

    if SNS_TOPIC_ARN:
        try:
            attrs = client("sns").get_topic_attributes(TopicArn=SNS_TOPIC_ARN)["Attributes"]
            services.append({"name": "Amazon SNS", "status": "Configured", "detail": f"Topic: {attrs.get('TopicArn', SNS_TOPIC_ARN)}"})
        except Exception as exc:
            services.append({"name": "Amazon SNS", "status": "Error", "detail": error_text(exc)})
    else:
        services.append({"name": "Amazon SNS", "status": "Not configured", "detail": "Optional: set SNS_TOPIC_ARN."})

    if IOT_ENDPOINT:
        try:
            # Endpoint configuration can be verified; this does not prove a device is connected.
            endpoint = client("iot").describe_endpoint(endpointType="iot:Data-ATS").get("endpointAddress", IOT_ENDPOINT)
            services.append({"name": "AWS IoT Core", "status": "Endpoint found", "detail": endpoint})
        except Exception as exc:
            services.append({"name": "AWS IoT Core", "status": "Error", "detail": error_text(exc)})
    else:
        services.append({"name": "AWS IoT Core", "status": "Not configured", "detail": "Optional: set IOT_ENDPOINT."})

    services.append({"name": "MQTT", "status": "Configured" if IOT_ENDPOINT and MQTT_TOPIC else "Not configured",
                     "detail": f"Topic: {MQTT_TOPIC}; broker connectivity is not tested by this dashboard."})
    services.append({"name": "ESP32 device", "status": "Not connected", "detail": "Physical hardware is planned and not required."})
    return services


def publish_iot_status(status, checked_at):
    if not DASHBOARD_PUBLISH_IOT:
        return {"status": "Not published by dashboard", "detail": "Assumed handled by Lambda or left disabled to avoid duplicate messages."}
    if not IOT_ENDPOINT:
        return {"status": "Not configured", "detail": "Set IOT_ENDPOINT before enabling dashboard publishing."}
    try:
        endpoint = IOT_ENDPOINT
        if "://" in endpoint:
            endpoint = endpoint.split("://", 1)[1].split("/", 1)[0]
        iot_data = aws_session().client("iot-data", region_name=AWS_REGION, endpoint_url=f"https://{endpoint}")
        message = {"status": status, "timestamp": checked_at, "source": "security-dashboard"}
        iot_data.publish(topic=MQTT_TOPIC, qos=1, payload=json.dumps(message).encode("utf-8"))
        return {"status": "Published", "detail": f"Published status JSON to {MQTT_TOPIC}."}
    except Exception as exc:
        return {"status": "Publish error", "detail": error_text(exc)}


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def api_status():
    if DEMO_MODE:
        state = read_state()
        latest = state.get("latest")
        return jsonify({
            "ok": True, "demo_mode": True, "region": AWS_REGION,
            "bucket": {"status": "Demo only", "bucket": S3_BUCKET_NAME or "Sample project bucket", "region": AWS_REGION,
                       "public_access_block": "Simulated — not checked against AWS", "error": "Demo mode: no AWS calls are made."},
            "services": [
                {"name": "Amazon S3", "status": "Demo only", "detail": "Sample card; not connected to AWS."},
                {"name": "AWS Lambda", "status": "Demo only", "detail": "Sample security result; Lambda is not invoked in demo mode."},
                {"name": "Amazon SNS", "status": "Demo only", "detail": "Notifications are not sent in demo mode."},
                {"name": "AWS IoT Core", "status": "Demo only", "detail": "No IoT endpoint is contacted in demo mode."},
                {"name": "MQTT", "status": "Demo only", "detail": f"Sample topic: {MQTT_TOPIC}; no message is published."},
                {"name": "ESP32 device", "status": "Not connected", "detail": "Physical hardware is optional."}],
            "latest": latest, "events": state.get("events", [])[:30],
            "mqtt": {"topic": MQTT_TOPIC, "latest_message": latest.get("status") if latest else "Demo not run yet",
                     "last_message_time": latest.get("checked_at") if latest else None,
                     "device_status": "Not connected", "publish_mode": "Demo only — publishing disabled"},
            "last_updated": now_iso(), "state_warning": state.get("state_warning", "")
        })
    state = read_state()
    s3 = get_s3_info()
    services = get_service_status()
    latest = state.get("latest")
    return jsonify({
        "ok": True,
        "region": AWS_REGION,
        "bucket": s3,
        "services": services,
        "latest": latest,
        "events": state.get("events", [])[:30],
        "mqtt": {
            "topic": MQTT_TOPIC,
            "latest_message": latest.get("status") if latest else "No message observed by dashboard",
            "last_message_time": latest.get("checked_at") if latest else None,
            "device_status": "Not connected",
            "publish_mode": "Dashboard publishing enabled" if DASHBOARD_PUBLISH_IOT else "Dashboard publishing disabled",
        },
        "last_updated": now_iso(),
        "state_warning": state.get("state_warning", ""),
    })


@app.post("/api/check")
def api_check():
    if DEMO_MODE:
        state = read_state()
        previous = (state.get("latest") or {}).get("status")
        status = "ALERT" if previous == "SAFE" else "SAFE"
        checked_at = now_iso()
        message = ("DEMO RESULT: sample security condition passed. This is not a live AWS evaluation."
                   if status == "SAFE" else "DEMO RESULT: sample security condition failed. This is not a live AWS evaluation.")
        latest = {"status": status, "checked_at": checked_at, "message": message,
                  "condition": "Simulated demonstration condition", "lambda_function": "Demo mode (Lambda not invoked)",
                  "iot_publish": {"status": "Demo only", "detail": "No MQTT message was published."}}
        state["latest"] = latest
        state.setdefault("events", []).insert(0, {"time": checked_at, "event": "Demo security evaluation", "status": status,
                                                   "source": "Local demo (not AWS)", "detail": message})
        state["events"] = state["events"][:100]
        write_state(state)
        return jsonify({"ok": True, "demo_mode": True, "latest": latest, "iot_publish": latest["iot_publish"]})
    if not LAMBDA_FUNCTION_NAME:
        return jsonify({"ok": False, "error": "LAMBDA_FUNCTION_NAME is missing in .env. Configure your existing security-check Lambda first."}), 400
    try:
        response = client("lambda").invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps({"source": "security-dashboard", "requested_at": now_iso()}).encode("utf-8"),
        )
        payload = response["Payload"].read()
        if response.get("FunctionError"):
            raise RuntimeError(f"Lambda execution failed: {payload.decode('utf-8', errors='replace')}")
        result = extract_lambda_result(payload)
        checked_at = now_iso()
        publish_result = publish_iot_status(result["status"], checked_at)
        latest = {
            "status": result["status"],
            "checked_at": checked_at,
            "message": result.get("message") or ("Security condition passed." if result["status"] == "SAFE" else "Security condition failed."),
            "condition": result.get("condition") or "Condition details were not included in the Lambda response.",
            "lambda_function": LAMBDA_FUNCTION_NAME,
            "iot_publish": publish_result,
        }
        state = read_state()
        state["latest"] = latest
        event = {
            "time": checked_at,
            "event": "S3 security evaluation",
            "status": result["status"],
            "source": f"Lambda: {LAMBDA_FUNCTION_NAME}",
            "detail": latest["message"],
        }
        state.setdefault("events", []).insert(0, event)
        if publish_result["status"] == "Published":
            state["events"].insert(0, {"time": checked_at, "event": "MQTT status published", "status": result["status"],
                                       "source": "Dashboard → AWS IoT Core", "detail": publish_result["detail"]})
        state["events"] = state["events"][:100]
        write_state(state)
        return jsonify({"ok": True, "latest": latest, "iot_publish": publish_result})
    except Exception as exc:
        message = error_text(exc)
        add_event("Security check failed to run", "ERROR", "Dashboard / AWS Lambda", message)
        return jsonify({"ok": False, "error": message}), 502


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True, "application": "running", "time": now_iso()})


if __name__ == "__main__":
    # Local-only development server. Do not expose this directly to the public internet.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
