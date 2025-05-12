import requests

BOT_TOKEN = '8197673232:AAHDLf5UvAJQ0zSyJJTanW_1B4uScXuxWIU'
CHAT_ID = '1688882252'
def get_chat_id():
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
    response = requests.get(url)
    print(response.json())

def send_telegram_alert(message):
    BOT_TOKEN = '8197673232:AAHDLf5UvAJQ0zSyJJTanW_1B4uScXuxWIU'
    CHAT_ID = '1688882252'

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"  # Optional: use Markdown formatting
    }

    try:
        requests.post(url, data=data)
    except Exception as e:
        print(f"[!] Telegram send failed: {e}")
