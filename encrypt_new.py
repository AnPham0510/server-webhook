#!/usr/bin/env python3
import hmac
import hashlib
import base64
from datetime import datetime, timezone
import requests
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Cấu hình HMAC
USER = "gino"
SECRET = "yVhB78mrRZz5Ugmhz0aHD8teGueqjCrGySQeJrnXmSM="
ALGORITHM = "hmac-sha256"

# AES-256-CBC key/iv (Base64)
ENCRYPTION_KEY = "gykG69sHMt0lQP8WUjDhJywG9famHh+R2mYgVcLO9sE="
IV = "R+HpD6sEVQ8vvSFAg/2/3g=="

URL = "https://gw.f88.co/sit/partner/store/api/v2/Webhook/Chip"
PATH_ONLY = "/sit/partner/store/api/v2/Webhook/Chip"
METHOD = "post"

BODY = {
    "DeviceCode": "G006977",
    "Status": 1,
    "Condition": 1,
    "ShopCode": "PGG Ginno",
    "CreatedTime": 1762159941,
    "CreatedUserName": "quanlygd@ginno.com"
}
def aes_encrypt_json_to_b64(json_str: str, key_b64: str, iv_b64: str) -> str:
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(json_str.encode("utf-8"), AES.block_size)
    ct = cipher.encrypt(padded)
    return base64.b64encode(ct).decode("utf-8")

def aes_decrypt_b64_to_text(ciphertext_b64: str, key_b64: str, iv_b64: str) -> str:
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode("utf-8")

def main():
    # 1) Serialize JSON gốc của body
    body_json = json.dumps(BODY, separators=(",", ":"))
    print("=" * 60)
    print("REQUEST - ORIGINAL BODY (Before Encryption)")
    print("=" * 60)
    print(body_json)
    print()

    # 2) Encrypt body -> base64(ciphertext)
    encrypted_body_b64 = aes_encrypt_json_to_b64(body_json, ENCRYPTION_KEY, IV)
    print("=" * 60)
    print("REQUEST - ENCRYPTED BODY (ciphertext base64)")
    print("=" * 60)
    print(encrypted_body_b64)
    print()

    # 3) Đóng gói payload JSON theo plugin: {"data": "<base64(ciphertext)>"}
    payload_obj = {"data": encrypted_body_b64}
    payload_json = json.dumps(payload_obj, separators=(",", ":"))
    print("=" * 60)
    print("REQUEST - PAYLOAD JSON (to send)")
    print("=" * 60)
    print(payload_json)
    print()

    # 4) Date/Digest/HMAC phải tính trên payload_json
    date_hdr = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    body_hash = hashlib.sha256(payload_json.encode("utf-8")).digest()
    body_hash_b64 = base64.b64encode(body_hash).decode("utf-8")
    digest = f"SHA-256={body_hash_b64}"

    request_target = f"{METHOD} {PATH_ONLY}"
    signing_string = f"date: {date_hdr}\n@request-target: {request_target}\ndigest: {digest}"

    signature = base64.b64encode(
        hmac.new(SECRET.encode("utf-8"), signing_string.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")

    auth_header = (
        f'hmac username="{USER}", algorithm="{ALGORITHM}", headers="date @request-target digest", signature="{signature}"'
    )

    headers = {
        "Date": date_hdr,
        "Digest": digest,
        "Authorization": auth_header,
        "Accept": "application/json",
        "Content-Type": "application/json",
        # Plugin của bạn đã bỏ requirement X-Encrypted, nên không cần header này nữa.
        # "X-Encrypted": "true",
    }

    print("=" * 60)
    print("HMAC SIGNING DETAILS")
    print("=" * 60)
    print(f"Date: {date_hdr}")
    print(f"Digest: {digest}")
    print(f"@request-target: {request_target}")
    print("Canonical String:")
    print(signing_string)
    print(f"Signature: {signature}")
    print()

    # 5) Gửi request với payload_json
    print("=" * 60)
    print("SENDING REQUEST TO SERVER...")
    print("=" * 60)
    print()

    resp = requests.post(URL, headers=headers, data=payload_json, timeout=30)

    print("=" * 60)
    print("RESPONSE - STATUS & HEADERS")
    print("=" * 60)
    print(f"Status Code: {resp.status_code}")
    for k, v in resp.headers.items():
        print(f"  {k}: {v}")
    print()

    resp_text = resp.text or ""
    print("=" * 60)
    print("RESPONSE - RAW BODY (As Received)")
    print("=" * 60)
    print(resp_text)
    print()

    # 6) Thử parse JSON và giải mã nếu có 'data'
    try:
        resp_json = resp.json()
    except Exception:
        resp_json = None

    if isinstance(resp_json, dict) and "data" in resp_json:
        encrypted_resp_b64 = resp_json["data"]
        print("=" * 60)
        print("ATTEMPTING TO DECRYPT RESPONSE...")
        print("=" * 60)
        try:
            decrypted = aes_decrypt_b64_to_text(encrypted_resp_b64, ENCRYPTION_KEY, IV)
            print("✅ DECRYPTION SUCCESSFUL!")
            print("=" * 60)
            print("RESPONSE - DECRYPTED TEXT")
            try:
                print(json.dumps(json.loads(decrypted), indent=2, ensure_ascii=False))
            except Exception:
                print(decrypted)
            print()
        except Exception as e:
            print("❌ DECRYPTION FAILED!")
            print(f"Error: {type(e).__name__}: {e}")
            print()
    else:
        if resp_json is not None:
            print("Response JSON (parsed):")
            print(json.dumps(resp_json, indent=2, ensure_ascii=False))
            print()
        else:
            print("Response is not JSON; skipping decryption.")
            print()

if __name__ == "__main__":
    main()