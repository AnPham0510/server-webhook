from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime

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

# Route chính để nhận webhook
@app.route('/webhook', methods=['POST'])
def handle_webhook():
    try:
        # Lấy dữ liệu từ request
        data = request.get_json()
        headers = dict(request.headers)
        
        # Log thông tin webhook
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info(f"Webhook received at {timestamp}")
        logging.info(f"Headers: {headers}")
        logging.info(f"Data: {json.dumps(data, indent=2, ensure_ascii=False)}")
        
        # Xử lý dữ liệu (tùy chỉnh theo nhu cầu)
        if isinstance(data, list):
            response_data = [process_webhook_data(item) for item in data]
        else:
            response_data = process_webhook_data(data)
        
        # Forward dữ liệu đã nhận sang Gapo endpoint
        forwarded, forward_response = forward_to_gapo(data)

        # Trả về response thành công
        return jsonify({
            'status': 'success',
            'message': 'Webhook received successfully',
            'timestamp': timestamp,
            'processed_data': response_data,
            'processed_data': response_data,
            'forwarded_to_gapo': forwarded,
            'gapo_response': forward_response
        }), 200
        
    except Exception as e:
        logging.error(f"Error processing webhook: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

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
                'is_markdown_text': True
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
    print("Webhook endpoint: http://localhost:6000/webhook")
    print("Health check: http://localhost:6000/health")
    print("Logs: http://localhost:6000/logs")
    print("Secure webhook: http://localhost:6000/webhook-secure")
    
    # Chạy server
    app.run(
        host='0.0.0.0',  # Cho phép truy cập từ bên ngoài
        port=6000,       # Cổng 6000
        debug=True       # Bật debug mode để development
    )