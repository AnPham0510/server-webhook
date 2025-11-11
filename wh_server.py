#!/usr/bin/env python3
from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime
import requests
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Cấu hình logging để theo dõi webhook requests
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webhook.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

# Cấu hình cho Gapo endpoint
GAPO_ENDPOINT = 'https://api.gapowork.vn/3rd-bot/v1.0/3rd/messages'
GAPO_API_KEY = '5dca5dec1ccb4445a501a1b7407c7d29'
GAPO_COLLAB_ID = 7005049350530566144
GAPO_BOT_ID = 5844770830816384526

# Thêm cấu hình tương ứng với client encrypt.py
ENCRYPTION_KEY = "gykG69sHMt0lQP8WUjDhJywG9famHh+R2mYgVcLO9sE="
IV = "R+HpD6sEVQ8vvSFAg/2/3g=="

# Thêm hằng số cho error codes và messages
ERROR_MESSAGES = {
    "400": "Truyền thiếu tham số bắt buộc hoặc thông tin truyền vào không đúng định dạng",
    "001": "Lỗi xử lý dữ liệu"
}

# AES helper: encrypt JSON text -> base64, decrypt base64 -> text
def aes_encrypt_json_to_b64(json_str: str, key_b64: str = ENCRYPTION_KEY, iv_b64: str = IV) -> str:
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

def aes_decrypt_b64(ciphertext_b64: str, key_b64: str = ENCRYPTION_KEY, iv_b64: str = IV) -> str:
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def get_request_json(req):
    """
    Trả về Python object từ request:
    - nếu request.get_json() thành công thì dùng luôn
      - nếu là wrapper {"data": "<b64>"} thì giải mã và trả nội dung bên trong
    - nếu không thì thử: raw text -> JSON, hoặc base64->AES decrypt->JSON
    Nếu không decode được sẽ raise ValueError để handler trả về lỗi rõ hơn.
    """
    # Thử dùng flask parsing trước (im lặng, không raise)
    data = req.get_json(silent=True)
    if data is not None:
        # Nếu là wrapper {"data": "<b64>"} -> giải mã và trả content
        if isinstance(data, dict) and 'data' in data and isinstance(data['data'], str):
            try:
                decrypted = aes_decrypt_b64(data['data'])
                # Đánh dấu request đã được mã hóa để response có thể mã hóa nếu cần
                req.environ['was_encrypted'] = True
                return json.loads(decrypted)
            except Exception as e:
                raise ValueError(f"Failed to decrypt 'data' field: {e}")
        return data

    raw = req.get_data(as_text=False)
    if not raw:
        raise ValueError("Empty request body")

    try:
        text = raw.decode('utf-8').strip()
    except Exception:
        # không phải utf-8, cố gắng coi là base64 với latin1 fallback
        text = raw.decode('latin1').strip()

    # Thử parse thẳng JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and 'data' in parsed and isinstance(parsed['data'], str):
            try:
                decrypted = aes_decrypt_b64(parsed['data'])
                req.environ['was_encrypted'] = True
                return json.loads(decrypted)
            except Exception as e:
                raise ValueError(f"Failed to decrypt 'data' field: {e}")
        return parsed
    except Exception:
        pass

    # Thử dạng base64->JSON (nếu client chỉ gửi base64 của JSON)
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        return json.loads(decoded)
    except Exception:
        pass

    # Thử base64->AES decrypt->JSON (client gửi trực tiếp ciphertext base64)
    try:
        decrypted = aes_decrypt_b64(text)
        req.environ['was_encrypted'] = True
        return json.loads(decrypted)
    except Exception as e:
        # Không decode được, ném lỗi rõ
        raise ValueError(f"Failed to decode JSON object: {e}")

def send_response(obj: dict, status_code: int = 200, req=None):
    """
    Nếu req.environ['was_encrypted'] == True thì trả payload {"data": "<b64>", "encrypted": true, "timestamp": ...}
    Ngược lại trả JSON bình thường.
    """
    try:
        should_encrypt = False
        if req is not None:
            should_encrypt = bool(req.environ.get('was_encrypted', False))
        if should_encrypt:
            payload_json = json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
            encrypted_b64 = aes_encrypt_json_to_b64(payload_json)
            resp_payload = {
                "data": encrypted_b64,
                "encrypted": True,
                "timestamp": int(time.time())
            }
            return jsonify(resp_payload), status_code
        else:
            return jsonify(obj), status_code
    except Exception as e:
        logging.error(f"Error creating encrypted response: {e}")
        return jsonify({
            "ErrorCode": "001",
            "Message": ERROR_MESSAGES["001"]
        }), 500

@app.route('/api/v2/Webhook/Chip/', methods=['POST', 'PUT'])
def handle_upsert_webhook():
    try:
        data = get_request_json(request)
        headers = dict(request.headers)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Webhook received at {timestamp}")
        logging.info(f"Headers: {headers}")
        logging.info(f"Data: {json.dumps(data, indent=2, ensure_ascii=False)}")

        if isinstance(data, list):
            response_data = [process_webhook_data(item) for item in data]
        else:
            response_data = process_webhook_data(data)

        forwarded, forward_response = forward_to_gapo(data)

        resp_obj = {
            'IsSuccess': True,
            'Message': "Nhận thông tin thành công",
            'Data': {
                'processed_data': response_data,
                'forwarded_to_gapo': forwarded,
                'gapo_response': forward_response,
                'timestamp': timestamp
            }
        }
        return send_response(resp_obj, 200, req=request)

    except ValueError as ve:
        err = {
            'ErrorCode': '400',
            'Message': ERROR_MESSAGES['400']
        }
        return send_response(err, 400, req=request)

    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        err = {
            'ErrorCode': '001',
            'Message': ERROR_MESSAGES['001']
        }
        return send_response(err, 400, req=request)

@app.route('/api/v2/Webhook/Chip/ActiveOrRetrieve', methods=['POST', 'PUT'])
def handle_activeOrRetrieve_webhook():
    try:
        data = get_request_json(request)
        headers = dict(request.headers)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Webhook received at {timestamp}")
        logging.info(f"Headers: {headers}")
        logging.info(f"Data: {json.dumps(data, indent=2, ensure_ascii=False)}")

        if isinstance(data, list):
            response_data = [process_webhook_data(item) for item in data]
        else:
            response_data = process_webhook_data(data)

        forwarded, forward_response = forward_to_gapo(data)

        resp_obj = {
            'IsSuccess': True,
            'Message': "Nhận thông tin thành công",
            'Data': {
                'processed_data': response_data,
                'forwarded_to_gapo': forwarded,
                'gapo_response': forward_response,
                'timestamp': timestamp
            }
        }
        return send_response(resp_obj, 200, req=request)

    except ValueError as ve:
        err = {
            'ErrorCode': '400',
            'Message': ERROR_MESSAGES['400']
        }
        return send_response(err, 400, req=request)

    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        err = {
            'ErrorCode': '001',
            'Message': ERROR_MESSAGES['001']
        }
        return send_response(err, 400, req=request)

@app.route('/api/v2/Webhook/Chip/Inventory', methods=['POST', 'PUT'])
def handle_inventory_webhook():
    try:
        data = get_request_json(request)
        headers = dict(request.headers)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Webhook received at {timestamp}")
        logging.info(f"Headers: {headers}")
        logging.info(f"Data: {json.dumps(data, indent=2, ensure_ascii=False)}")

        if isinstance(data, list):
            response_data = [process_webhook_data(item) for item in data]
        else:
            response_data = process_webhook_data(data)

        forwarded, forward_response = forward_to_gapo(data)

        resp_obj = {
            'IsSuccess': True,
            'Message': "Nhận thông tin thành công",
            'Data': {
                'processed_data': response_data,
                'forwarded_to_gapo': forwarded,
                'gapo_response': forward_response,
                'timestamp': timestamp
            }
        }
        return send_response(resp_obj, 200, req=request)

    except ValueError as ve:
        err = {
            'ErrorCode': '400',
            'Message': ERROR_MESSAGES['400']
        }
        return send_response(err, 400, req=request)

    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        err = {
            'ErrorCode': '001',
            'Message': ERROR_MESSAGES['001']
        }
        return send_response(err, 400, req=request)

@app.route('/api/v2/Webhook/Chip/Sync', methods=['POST', 'PUT'])
def handle_report_webhook():
    try:
        data = get_request_json(request)
        headers = dict(request.headers)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Webhook received at {timestamp}")
        logging.info(f"Headers: {headers}")
        logging.info(f"Data: {json.dumps(data, indent=2, ensure_ascii=False)}")

        if isinstance(data, list):
            response_data = [process_webhook_data(item) for item in data]
        else:
            response_data = process_webhook_data(data)

        forwarded, forward_response = forward_to_gapo(data)

        resp_obj = {
            'IsSuccess': True,
            'Message': "Nhận thông tin thành công",
            'Data': {
                'processed_data': response_data,
                'forwarded_to_gapo': forwarded,
                'gapo_response': forward_response,
                'timestamp': timestamp
            }
        }
        return send_response(resp_obj, 200, req=request)

    except ValueError as ve:
        err = {
            'ErrorCode': '400',
            'Message': ERROR_MESSAGES['400']
        }
        return send_response(err, 400, req=request)

    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        err = {
            'ErrorCode': '001',
            'Message': ERROR_MESSAGES['001']
        }
        return send_response(err, 400, req=request)

# Route chính để nhận webhook
@app.route('/webhook', methods=['POST', 'PUT'])
def handle_webhook():
    try:
        data = get_request_json(request)
        headers = dict(request.headers)

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Webhook received at {timestamp}")
        logging.info(f"Headers: {headers}")
        logging.info(f"Data: {json.dumps(data, indent=2, ensure_ascii=False)}")

        if isinstance(data, list):
            response_data = [process_webhook_data(item) for item in data]
        else:
            response_data = process_webhook_data(data)

        forwarded, forward_response = forward_to_gapo(data)

        resp_obj = {
            'IsSuccess': True,
            'Message': "Nhận thông tin thành công",
            'Data': {
                'processed_data': response_data,
                'forwarded_to_gapo': forwarded,
                'gapo_response': forward_response,
                'timestamp': timestamp
            }
        }
        return send_response(resp_obj, 200, req=request)

    except ValueError as ve:
        err = {
            'ErrorCode': '400',
            'Message': ERROR_MESSAGES['400']
        }
        return send_response(err, 400, req=request)

    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        err = {
            'ErrorCode': '001',
            'Message': ERROR_MESSAGES['001']
        }
        return send_response(err, 400, req=request)

def process_webhook_data(data):
    """
    Hàm xử lý dữ liệu webhook - tùy chỉnh theo nhu cầu của bạn
    """
    if isinstance(data, dict):
        processed = {
            'received_keys': list(data.keys()) if data else [],
            'data_count': len(data) if data else 0,
            'processing_time': datetime.now().isoformat()
        }
        # Ví dụ: xử lý một số loại dữ liệu cụ thể
        if data and 'user_id' in data:
            processed['user_processed'] = True
            processed['user_id'] = data['user_id']
        if data and 'event_type' in data:
            processed['event_type'] = data['event_type']
        return processed
    else:
        # Nếu không phải dict (ví dụ: primitive type), trả về thông tin cơ bản
        return {
            'received_type': str(type(data)),
            'value': data,
            'processing_time': datetime.now().isoformat()
        }

def forward_to_gapo(data):
    """
    Gửi dữ liệu nhận được tới Gapo endpoint dưới dạng text.
    - Nếu data không phải chuỗi, chuyển thành chuỗi JSON (giữ unicode).
    Trả về (bool, any): thành công/thất bại và nội dung phản hồi.
    """
    try:
        text_value = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        payload = {
            'collab_id': GAPO_COLLAB_ID,
            'bot_id': GAPO_BOT_ID,
            'body': {
                'type': 'text',
                'text': text_value,
                'is_markdown_text': False
            }
        }
        headers = {
            'Content-Type': 'application/json',
            'x-gapo-api-key': GAPO_API_KEY
        }
        response = requests.post(GAPO_ENDPOINT, headers=headers, json=payload, timeout=10)
        logging.info(f"Forward to Gapo - status: {response.status_code}, body: {response.text}")
        # Raise nếu mã lỗi
        response.raise_for_status()
        if 'application/json' in (response.headers.get('Content-Type') or ''):
            return True, response.json()
        return True, response.text
    except Exception as e:
        logging.error(f"Error forwarding to Gapo: {str(e)}")
        return False, str(e)

# Route để kiểm tra server có hoạt động không
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'message': 'Webhook server is running'
    })

# Route để xem log gần đây (tùy chọn)
@app.route('/logs', methods=['GET'])
def get_recent_logs():
    try:
        with open('webhook.log', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            recent_logs = lines[-50:]  # Lấy 50 dòng cuối
        return jsonify({
            'logs': recent_logs,
            'count': len(recent_logs)
        })
    except FileNotFoundError:
        return jsonify({'message': 'No logs found'})

# Route với authentication (tùy chọn)
@app.route('/webhook-secure', methods=['POST'])
def handle_secure_webhook():
    # Kiểm tra API key hoặc token
    api_key = request.headers.get('X-API-Key')
    expected_key = 'your-secret-api-key-here'  # Thay đổi theo nhu cầu

    if api_key != expected_key:
        return jsonify({'error': 'Unauthorized'}), 401

    # Xử lý giống như webhook thường
    return handle_webhook()

if __name__ == '__main__':
    print("Starting Webhook Server...")
    print("Webhook endpoint: http://localhost:5000/webhook")
    print("Health check: http://localhost:5000/health")
    print("Logs: http://localhost:5000/logs")
    print("Secure webhook: http://localhost:5000/webhook-secure")

    # Chạy server
    app.run(
        host='192.168.1.32',  # Cho phép truy cập từ bên ngoài
        port=8000,       # Cổng 5000
        debug=True       # Bật debug mode để development
    )