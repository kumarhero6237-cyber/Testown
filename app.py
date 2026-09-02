"""
Free Fire India-only player information API.

Important deployment note:
- This app keeps its token/cache warm only while the Python process is alive.
- Vercel Python functions are serverless and may be frozen/restarted, so no Python
  background thread can guarantee "always on" there.
- For true always-on behaviour, run this app as a persistent Gunicorn service
  (VPS / paid always-on container / similar).
"""

import asyncio
import base64
import json
import threading
import time
from functools import wraps
from typing import Tuple

import httpx
from flask import Flask, jsonify, request
from flask_cors import CORS
from google.protobuf import json_format, message
from Crypto.Cipher import AES

from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2

# ---------------- Config ----------------

MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# Hard India-only policy.
INDIA_REGIONS = {"IND", "INDIA", "IN"}

# Keep your existing key; preferably move it to an environment variable in production.
API_KEY = "RAM-SAGAR"

TOKEN_REFRESH_SAFETY = 300          # refresh 5 minutes before expiry
TOKEN_FALLBACK_TTL = 25200          # 7 hours if server does not provide TTL
REQUEST_TIMEOUT = httpx.Timeout(8.0, connect=3.0)
MAX_CONNECTIONS = 50
MAX_KEEPALIVE = 20

app = Flask(__name__)
CORS(app)

# ---------------- Persistent async worker ----------------

_loop = None
_loop_ready = threading.Event()
_loop_lock = threading.Lock()
_http_client = None
_token_lock = None
_cached_token = None


def _start_async_worker():
    global _loop

    with _loop_lock:
        if _loop is not None:
            return
        _loop = asyncio.new_event_loop()

    def runner():
        asyncio.set_event_loop(_loop)
        _loop.run_until_complete(_async_startup())
        _loop_ready.set()
        _loop.run_forever()

    threading.Thread(target=runner, name="ff-api-async", daemon=True).start()


async def _async_startup():
    global _http_client, _token_lock
    _http_client = httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        limits=httpx.Limits(
            max_connections=MAX_CONNECTIONS,
            max_keepalive_connections=MAX_KEEPALIVE,
            keepalive_expiry=30.0,
        ),
        http2=False,
        headers={
            "User-Agent": USERAGENT,
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip",
        },
    )
    _token_lock = asyncio.Lock()
    # Warm token once, but do not make process startup fail if Garena is temporarily slow.
    try:
        await create_jwt()
    except Exception as exc:
        print(f"⚠️ Initial India token warm-up failed: {exc}")

    asyncio.create_task(refresh_tokens_periodically())


def _run(coro):
    """Run a coroutine on the single persistent event loop."""
    _start_async_worker()
    _loop_ready.wait(timeout=10)
    if _loop is None or not _loop.is_running():
        raise RuntimeError("Async worker is not running")
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result(timeout=15)


# ---------------- API key ----------------

def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.args.get("key") or request.headers.get("x-api-key")
        if key != API_KEY:
            return jsonify({"error": "Invalid or missing API key"}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------- Crypto / protobuf ----------------

def pad(data: bytes) -> bytes:
    padding_length = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([padding_length]) * padding_length


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))


def decode_protobuf(encoded_data: bytes, message_type: message.Message):
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance


async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


# ---------------- India guest account ----------------

def get_india_account() -> str:
    return "uid=7406125211&password=3C1CC07B85A500A28C1E0A8D1C90AB6C011B8A80E488E7AE7B8A15085D24CCF2"


# ---------------- Token generation ----------------

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        account
        + "&response_type=token&client_type=2"
        + "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        + "&client_id=100067"
    )
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    resp = await _http_client.post(url, data=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt():
    global _cached_token

    async with _token_lock:
        account = get_india_account()
        token_val, open_id = await get_access_token(account)
        if not token_val or token_val == "0" or not open_id or open_id == "0":
            raise RuntimeError("India guest token was not returned")

        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4",
        })

        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            "User-Agent": USERAGENT,
            "Connection": "keep-alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASEVERSION,
        }

        resp = await _http_client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"MajorLogin status {resp.status_code}")

        decoded = decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
        msg = json.loads(json_format.MessageToJson(decoded))

        lock_region = str(msg.get("lockRegion", "")).upper()
        if lock_region not in INDIA_REGIONS:
            raise RuntimeError(f"India token returned unexpected region: {lock_region or 'unknown'}")

        server_url = msg.get("serverUrl")
        game_token = msg.get("token")
        if not server_url or not game_token:
            raise RuntimeError("MajorLogin did not return token/server")

        try:
            ttl = int(msg.get("ttl", TOKEN_FALLBACK_TTL))
        except (TypeError, ValueError):
            ttl = TOKEN_FALLBACK_TTL

        # Never trust an extremely long server TTL.
        ttl = max(600, min(ttl, TOKEN_FALLBACK_TTL))

        _cached_token = {
            "token": f"Bearer {game_token}",
            "region": lock_region,
            "server_url": server_url.rstrip("/"),
            "expires_at": time.time() + ttl,
        }

        print(f"✅ INDIA TOKEN READY -> {server_url} | TTL={ttl}s")
        return True


async def refresh_tokens_periodically():
    while True:
        try:
            await asyncio.sleep(60)
            if not _cached_token or time.time() >= _cached_token["expires_at"] - TOKEN_REFRESH_SAFETY:
                try:
                    await create_jwt()
                except Exception as exc:
                    print(f"⚠️ India token refresh failed: {exc}")
        except asyncio.CancelledError:
            return
        except Exception as exc:
            print(f"⚠️ Token refresh loop error: {exc}")
            await asyncio.sleep(10)


async def get_token_info() -> Tuple[str, str, str]:
    if _cached_token and time.time() < _cached_token["expires_at"] - 30:
        return (
            _cached_token["token"],
            _cached_token["region"],
            _cached_token["server_url"],
        )

    await create_jwt()
    if not _cached_token:
        raise RuntimeError("Failed to generate India token")

    return (
        _cached_token["token"],
        _cached_token["region"],
        _cached_token["server_url"],
    )


# ---------------- Player lookup ----------------

async def GetAccountInformation(uid, unk):
    payload = await json_to_proto(
        json.dumps({"a": uid, "b": unk}),
        main_pb2.GetPlayerPersonalShow(),
    )

    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock_region, server = await get_token_info()

    if lock_region.upper() not in INDIA_REGIONS:
        raise RuntimeError("Only India region token is allowed")

    headers = {
        "User-Agent": USERAGENT,
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "Authorization": token,
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION,
    }

    endpoint = server.rstrip("/") + "/GetPlayerPersonalShow"

    # One fast retry after refreshing the token for expired/invalid sessions.
    for attempt in range(2):
        resp = await _http_client.post(endpoint, data=data_enc, headers=headers)

        if resp.status_code == 401 and attempt == 0:
            await create_jwt()
            token, _, server = await get_token_info()
            headers["Authorization"] = token
            endpoint = server.rstrip("/") + "/GetPlayerPersonalShow"
            continue

        if resp.status_code != 200:
            raise RuntimeError(f"Game server returned status {resp.status_code}")

        content_type = resp.headers.get("content-type", "").lower()
        if "application/octet-stream" not in content_type:
            raise RuntimeError(f"Unexpected content type: {content_type}")

        decoded = decode_protobuf(
            resp.content,
            AccountPersonalShow_pb2.AccountPersonalShowInfo,
        )
        data = json.loads(json_format.MessageToJson(decoded))

        # HARD INDIA-ONLY CHECK.
        # The account response contains basic_info.region. If it is not India,
        # do not return the player's data to the caller.
        basic = data.get("basicInfo") or data.get("basic_info") or {}
        player_region = str(basic.get("region", "")).upper().strip()

        if player_region not in INDIA_REGIONS:
            raise ValueError("UID is not an India-region Free Fire account")

        # Return only the data belonging to this India account.
        return data

    raise RuntimeError("Player lookup failed")


# Start the persistent worker as soon as this module is imported.
_start_async_worker()


# ---------------- Routes ----------------

@app.route("/uc-info")
@require_api_key
def get_account_info():
    uid = request.args.get("uid", "").strip()

    if not uid:
        return jsonify({
            "error": "Please provide UID",
            "example": "/uc-info?uid=123456789&key=RAM-SAGAR",
        }), 400

    if not uid.isdigit():
        return jsonify({"error": "UID must be a valid number"}), 400

    if len(uid) > 15:
        return jsonify({"error": "UID is too long"}), 400

    try:
        data = _run(GetAccountInformation(uid, "7"))
        return jsonify(data)
    except ValueError as exc:
        return jsonify({
            "error": "UID is not available in the India region",
            "message": str(exc),
        }), 404
    except Exception as exc:
        print(f"❌ ERROR fetching UID {uid}: {exc}")
        return jsonify({
            "error": "Failed to fetch India player info",
            "details": str(exc),
        }), 502


@app.route("/ref-token", methods=["GET", "POST"])
@require_api_key
def refresh_tokens_endpoint():
    try:
        _run(create_jwt())
        return jsonify({
            "message": "India token refreshed successfully",
            "region": "IND",
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502


@app.route("/health")
def health():
    token_ready = bool(
        _cached_token and time.time() < _cached_token["expires_at"]
    )
    return jsonify({
        "status": "ok",
        "region": "IND",
        "token_ready": token_ready,
        "always_on_note": "Requires a persistent Python process; serverless platforms may sleep.",
    })


@app.route("/")
def home():
    return jsonify({
        "api": "UC India Only Free Fire Info API",
        "version": RELEASEVERSION,
        "region": "IND ONLY",
        "endpoints": {
            "/uc-info?uid=<UID>&key=RAM-SAGAR": "India player info only",
            "/ref-token?key=RAM-SAGAR": "Refresh India auth token",
            "/health": "Health check",
            "/": "API info",
        },
    })


# Graceful shutdown when the hosting process stops.
import atexit

@atexit.register
def _shutdown():
    global _loop, _http_client
    try:
        if _loop and _loop.is_running() and _http_client:
            future = asyncio.run_coroutine_threadsafe(_http_client.aclose(), _loop)
            future.result(timeout=2)
            _loop.call_soon_threadsafe(_loop.stop)
    except Exception:
        pass
