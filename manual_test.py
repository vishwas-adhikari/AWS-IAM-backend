import requests

# PASTE YOUR REAL DATA HERE MANUALLY
TOKEN = "8220129614:AAGyzGRN9pATFkNTFEn8NUdRkeuPor3la9I"
CHAT_ID = "1837106205"

def test_now():
    print(f"🚀 Sending manual test to Telegram...")
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": "✅ CloudLens Manual Connection Test: If you see this, your Bot and Token are working!",
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"❌ Network Error: {e}")

if __name__ == "__main__":
    test_now()