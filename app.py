import json
import os
import base64
import time
import hmac
import hashlib
from datetime import datetime, date
from decimal import Decimal

import boto3

ecs = boto3.client("ecs")
rds = boto3.client("rds")

# Credenciales de login (desde env vars)
VALID_USER = os.environ.get("DASH_USER")
VALID_PASS = os.environ.get("DASH_PASS")

# Config JWT
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ISSUER = "ecs-rds-dashboard"
JWT_AUDIENCE = "ecs-rds-dashboard-ui"
DEFAULT_TTL = int(os.environ.get("JWT_TTL_SECONDS", "1800"))  # 30 min por defecto


def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return float(o)
    raise TypeError(f"Type not serializable: {type(o)}")


def _response(status_code, body):
    # En prod: cambia "*" por el dominio del panel
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body, default=_json_default),
    }


# ========= JWT HS256 =========

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data_str: str) -> bytes:
    padding = "=" * (-len(data_str) % 4)
    return base64.urlsafe_b64decode(data_str + padding)


def _create_token(username: str, role: str = "admin", ttl_seconds: int = DEFAULT_TTL) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET no configurado")

    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _verify_token(token: str) -> dict:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET no configurado")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Formato de token inválido")

    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_sig, _b64url_decode(sig_b64)):
        raise ValueError("Firma de token inválida")

    payload_json = _b64url_decode(payload_b64).decode("utf-8")
    payload = json.loads(payload_json)

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise ValueError("Token expirado")

    if payload.get("iss") != JWT_ISSUER or payload.get("aud") != JWT_AUDIENCE:
        raise ValueError("Token con iss/aud inválidos")

    return payload


def _get_auth_token(event):
    headers = event.get("headers") or {}
    auth_header = headers.get("Authorization") or headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()


def _require_auth(event, require_admin=True):
    token = _get_auth_token(event)
    if not token:
        raise PermissionError("Token ausente")

    payload = _verify_token(token)
    role = payload.get("role", "read")

    if require_admin and role != "admin":
        raise PermissionError("Permisos insuficientes")

    return payload


# ========= ECS helpers =========

def list_all_ecs_services(cluster_filter=None):
    """
    Lista servicios ECS de todos los clusters, opcionalmente filtrando por nombre de cluster.
    """
    clusters = []
    paginator = ecs.get_paginator("list_clusters")
    for page in paginator.paginate():
        clusters.extend(page.get("clusterArns", []))

    services_info = []

    for cluster_arn in clusters:
        cluster_name = cluster_arn.split("/")[-1]

        if cluster_filter and cluster_name != cluster_filter:
            continue

        svc_paginator = ecs.get_paginator("list_services")
        service_arns = []
        for sp in svc_paginator.paginate(cluster=cluster_arn):
            service_arns.extend(sp.get("serviceArns", []))

        if not service_arns:
            continue

        for i in range(0, len(service_arns), 10):
            chunk = service_arns[i : i + 10]
            desc = ecs.describe_services(cluster=cluster_arn, services=chunk)
            for s in desc.get("services", []):
                services_info.append(
                    {
                        "clusterArn": cluster_arn,
                        "clusterName": cluster_name,
                        "serviceArn": s["serviceArn"],
                        "serviceName": s["serviceName"],
                        "status": s.get("status"),
                        "desiredCount": s.get("desiredCount"),
                        "runningCount": s.get("runningCount"),
                        "launchType": s.get("launchType"),
                        "createdAt": s.get("createdAt"),
                        "schedulingStrategy": s.get("schedulingStrategy"),
                    }
                )

    return services_info


def update_ecs_service_state(cluster_arn, service_name, action, desired_count=None):
    """
    action: "start" o "stop"
    - start: desired_count por defecto = 1 (o el que pases)
    - stop: desiredCount = 0
    """
    if action not in ["start", "stop"]:
        raise ValueError("action must be 'start' or 'stop'")

    if action == "stop":
        target_desired = 0
    else:
        if desired_count is None:
            desired_count = 1
        target_desired = int(desired_count)

    resp = ecs.update_service(
        cluster=cluster_arn,
        service=service_name,
        desiredCount=target_desired,
    )
    s = resp["service"]
    return {
        "clusterArn": cluster_arn,
        "serviceName": service_name,
        "newDesiredCount": s.get("desiredCount"),
        "runningCount": s.get("runningCount"),
        "status": s.get("status"),
    }


# ========= RDS helpers =========

def list_rds_instances(engine_filter=None, status_filter=None):
    """
    Lista instancias RDS (no clusters Aurora) con info básica.
    Puedes filtrar opcionalmente por engine y status.
    """
    instances = []
    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            engine = db.get("Engine")
            status = db.get("DBInstanceStatus")

            if engine_filter and engine != engine_filter:
                continue
            if status_filter and status != status_filter:
                continue

            instances.append(
                {
                    "dbInstanceIdentifier": db["DBInstanceIdentifier"],
                    "dbInstanceArn": db.get("DBInstanceArn"),
                    "engine": engine,
                    "engineVersion": db.get("EngineVersion"),
                    "dbInstanceClass": db.get("DBInstanceClass"),
                    "multiAZ": db.get("MultiAZ"),
                    "availabilityZone": db.get("AvailabilityZone"),
                    "status": status,
                    "endpoint": (db.get("Endpoint") or {}).get("Address"),
                    "allocatedStorage": db.get("AllocatedStorage"),
                    "storageType": db.get("StorageType"),
                    "clusterIdentifier": db.get("DBClusterIdentifier"),
                    "publiclyAccessible": db.get("PubliclyAccessible"),
                }
            )
    return instances


def update_rds_instance_state(db_instance_identifier, action):
    """
    action: "start" o "stop" sobre una instancia RDS clásica (no Aurora serverless).
    Usa rds:start_db_instance / stop_db_instance.
    """
    if action not in ["start", "stop"]:
        raise ValueError("action must be 'start' or 'stop'")

    if action == "start":
        resp = rds.start_db_instance(DBInstanceIdentifier=db_instance_identifier)
    else:
        resp = rds.stop_db_instance(DBInstanceIdentifier=db_instance_identifier)

    db = resp["DBInstance"]
    return {
        "dbInstanceIdentifier": db["DBInstanceIdentifier"],
        "status": db.get("DBInstanceStatus"),
        "engine": db.get("Engine"),
        "dbInstanceClass": db.get("DBInstanceClass"),
        "availabilityZone": db.get("AvailabilityZone"),
        "multiAZ": db.get("MultiAZ"),
    }


# ========= Lambda handler / routing =========

def lambda_handler(event, context):
    # Soporta Lambda URL y API GW (v1/v2)
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    )
    raw_path = event.get("rawPath") or event.get("path") or "/"
    path = raw_path.rstrip("/") or "/"

    # Preflight CORS
    if method == "OPTIONS":
        return _response(200, {"ok": True})

    try:
        # ---------- /login (POST, sin token todavía) ----------
        if method == "POST" and path == "/login":
            body = event.get("body") or "{}"
            if event.get("isBase64Encoded"):
                body = base64.b64decode(body).decode("utf-8")
            data = json.loads(body)

            user = (data.get("user") or "").strip()
            passwd = data.get("pass") or ""

            if not VALID_USER or not VALID_PASS:
                return _response(500, {"error": "DASH_USER/DASH_PASS no configurados"})

            if user != VALID_USER or passwd != VALID_PASS:
                return _response(401, {"error": "Credenciales inválidas"})

            token = _create_token(username=user, role="admin")
            return _response(
                200,
                {
                    "token": token,
                    "user": user,
                    "role": "admin",
                    "expiresIn": DEFAULT_TTL,
                },
            )

        # ---------- ECS: GET /services ----------
        if method == "GET" and path == "/services":
            qs = event.get("queryStringParameters") or {}
            cluster_filter = qs.get("cluster")
            _require_auth(event, require_admin=False)
            services = list_all_ecs_services(cluster_filter=cluster_filter)
            return _response(200, {"services": services})

        # ---------- ECS: POST /action ----------
        if method == "POST" and path == "/action":
            _require_auth(event, require_admin=True)

            body = event.get("body") or "{}"
            if event.get("isBase64Encoded"):
                body = base64.b64decode(body).decode("utf-8")
            data = json.loads(body)

            cluster_arn = data.get("clusterArn")
            service_name = data.get("serviceName")
            action = data.get("action")
            desired_count = data.get("desiredCount")

            if not cluster_arn or not service_name or not action:
                return _response(
                    400,
                    {
                        "error": "clusterArn, serviceName y action son obligatorios",
                        "received": data,
                    },
                )

            result = update_ecs_service_state(
                cluster_arn=cluster_arn,
                service_name=service_name,
                action=action,
                desired_count=desired_count,
            )
            return _response(200, {"result": result})

        # ---------- RDS: GET /rds/instances ----------
        if method == "GET" and path == "/rds/instances":
            qs = event.get("queryStringParameters") or {}
            engine_filter = qs.get("engine")
            status_filter = qs.get("status")
            _require_auth(event, require_admin=False)
            instances = list_rds_instances(
                engine_filter=engine_filter, status_filter=status_filter
            )
            return _response(200, {"instances": instances})

        # ---------- RDS: POST /rds/action ----------
        if method == "POST" and path == "/rds/action":
            _require_auth(event, require_admin=True)

            body = event.get("body") or "{}"
            if event.get("isBase64Encoded"):
                body = base64.b64decode(body).decode("utf-8")
            data = json.loads(body)

            db_id = data.get("dbInstanceIdentifier")
            action = data.get("action")

            if not db_id or not action:
                return _response(
                    400,
                    {
                        "error": "dbInstanceIdentifier y action son obligatorios",
                        "received": data,
                    },
                )

            result = update_rds_instance_state(
                db_instance_identifier=db_id,
                action=action,
            )
            return _response(200, {"result": result})

        # ---------- GET / → ping ----------
        if method == "GET" and path == "/":
            return _response(
                200,
                {
                    "message": "ECS+RDS Lambda control OK",
                    "hint": "Usa /login, /services, /action, /rds/instances y /rds/action",
                },
            )

        return _response(
            404, {"error": "Ruta no encontrada", "path": path, "method": method}
        )

    except PermissionError as e:
        return _response(401, {"error": str(e)})
    except ValueError as e:
        return _response(400, {"error": str(e)})
    except Exception as e:
        return _response(
            500,
            {
                "error": str(e),
                "info": "Revisa CloudWatch Logs para más detalle",
            },
        )