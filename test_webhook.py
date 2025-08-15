# test_webhook.py - Script để test gửi webhook
import requests
import json
from datetime import datetime

def test_webhook():
    """Test gửi dữ liệu webhook đến server"""
    
    # URL của webhook server (thay đổi nếu cần)
    webhook_url = "http://192.168.4.231:5000/webhook"
    
    # Dữ liệu test (dạng list)
    test_data = [
        {
            "event_type": "user_created",
            "user_id": "12345",
            "username": "test_user1",
            "email": "test1@example.com",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "source": "web_app",
                "ip_address": "192.168.1.1"
            }
        },
        {
            "event_type": "user_created",
            "user_id": "67890",
            "username": "test_user2",
            "email": "test2@example.com",
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "source": "web_app",
                "ip_address": "192.168.1.2"
            }
        }
    ]
    
    # Headers
    headers = {
        'Content-Type': 'application/json',
        'X-Source': 'test-script'
    }
    
    try:
        print("Gửi webhook...")
        print(f"URL: {webhook_url}")
        print(f"Data: {json.dumps(test_data, indent=2, ensure_ascii=False)}")
        
        response = requests.post(
            webhook_url, 
            json=test_data, 
            headers=headers,
            timeout=10
        )
        
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response: {response.json()}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def test_secure_webhook():
    """Test gửi webhook với authentication"""
    
    webhook_url = "http://192.168.4.231:5000/webhook-secure"
    
    test_data = {
        "event_type": "payment_completed",
        "transaction_id": "txn_123456",
        "amount": 100.00,
        "currency": "VND"
    }
    
    headers = {
        'Content-Type': 'application/json',
        'X-API-Key': 'your-secret-api-key-here'  # API key
    }
    
    try:
        print("\nGửi secure webhook...")
        response = requests.post(webhook_url, json=test_data, headers=headers)
        print(f"Secure Response: {response.json()}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def check_server_health():
    """Kiểm tra server có hoạt động không"""
    try:
        response = requests.get("http://localhost:5000/health")
        print(f"Health Check: {response.json()}")
    except:
        print("Server không hoạt động!")

if __name__ == "__main__":
    # Kiểm tra server
    check_server_health()
    
    # Test webhook thường
    test_webhook()
    
    # Test secure webhook
    test_secure_webhook()

# setup.py - Script setup môi trường
import subprocess
import sys

# def install_requirements():
#     """Cài đặt các package cần thiết"""
#     try:
#         subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "requests"])
#         print("✅ Đã cài đặt Flask và Requests")
#     except subprocess.CalledProcessError as e:
#         print(f"❌ Lỗi cài đặt: {e}")

def create_project_structure():
    """Tạo cấu trúc project"""
    import os
    
    # Tạo thư mục logs nếu chưa có
    if not os.path.exists('logs'):
        os.makedirs('logs')
        print("✅ Đã tạo thư mục logs")
    
    print("✅ Project setup hoàn tất!")

if __name__ == "__main__":
    # install_requirements()
    create_project_structure()