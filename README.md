# cybersecurity-chatbot
A secure chatbot with encrypted logging, threat monitoring, and real-time alerts.
# Chatbot with Logging & Security Monitoring

This chatbot logs conversations securely, detects suspicious activity, and implements multiple security measures, including encryption, authentication, and input sanitization.

## Features
- **AES-Encrypted Logs**: Stores chat messages securely.
- **Threat Monitoring**: Flags suspicious keywords (e.g., "hack", "phish").
- **User Authentication**: Requires a password before chatbot access.
- **Input Sanitization**: Prevents command injection.
- **Real-Time Alerts**: Sends an email if suspicious activity is detected.

## Installation
1. **Clone the repository**
   ```sh
   git clone https://github.com/yourusername/chatbot-security.git
   cd chatbot-security
   ```
2. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```

## Usage
Run the chatbot with:
```sh
python chatbot.py
```

### Authentication
When prompted, enter the access password:
```sh
Enter chatbot access password:
```
_Default password is "securepassword" (can be changed in the script)._

### Example Chat Session
```sh
Chatbot initialized. Type 'exit' to stop.
You: Hello
Chatbot: Message received.
You: I want to hack a system
[ALERT] Suspicious activity detected: I want to hack a system
```

## Viewing Encrypted Logs
Chat messages are encrypted in `chatbot_logs.txt`. To decrypt logs, add this function to the script:
```python
from cryptography.fernet import Fernet

def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message.encode()).decode()
```

## Customization
- Modify the `suspicious_keywords` set to adjust monitoring.
- Update email settings in `send_alert_email()` for real-time alerts.
- Change authentication behavior in `authenticate_user()`.

## Future Improvements
- Integrate with Splunk for advanced monitoring.
- Add a web-based UI for easier interaction.
- Implement a machine-learning model for smarter threat detection.

---
**Author:** Larion  
**License:** MIT  
**GitHub:** [https://github.com/Larionm/cybersecurity-chatbot/blob/main/Chatbot%20logs%20and%20monitors%20conversations.py]

