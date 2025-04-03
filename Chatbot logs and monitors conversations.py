import logging
from datetime import datetime
from cryptography.fernet import Fernet
import re
import getpass
import smtplib
from email.message import EmailMessage

# Generate or load encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_message(message):
    """Encrypts a message using AES encryption."""
    return cipher_suite.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message):
    """Decrypts an encrypted message."""
    return cipher_suite.decrypt(encrypted_message.encode()).decode()

# Configure logging
logging.basicConfig(
    filename="chatbot_logs.txt", 
    level=logging.INFO, 
    format="%(asctime)s - %(message)s"
)

# Define suspicious keywords
suspicious_keywords = {"hack", "phish", "exploit", "breach", "malware"}

def send_alert_email(alert_message):
    """Sends an email alert when suspicious activity is detected."""
    sender_email = "your_email@example.com"  # Replace with actual email
    recipient_email = "admin@example.com"  # Replace with actual admin email
    msg = EmailMessage()
    msg.set_content(alert_message)
    msg["Subject"] = "Security Alert: Suspicious Activity Detected"
    msg["From"] = sender_email
    msg["To"] = recipient_email
    
    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:  # Replace with actual SMTP server
            server.starttls()
            server.login("your_email@example.com", "your_password")  # Replace with actual credentials
            server.send_message(msg)
    except Exception as e:
        logging.error(f"Failed to send alert email: {e}")

def sanitize_input(user_input):
    """Sanitizes user input to prevent command injection attacks."""
    return re.sub(r'[^\w\s]', '', user_input)

def authenticate_user():
    """Simple user authentication before allowing chatbot access."""
    password = input("Enter chatbot access password: ")  # Use input() instead of getpass
    if password != "securepassword":
        print("Authentication failed. Exiting chatbot.")
        exit()


def monitor_chat(user_input):
    """Logs encrypted user input, sanitizes it, and flags potential threats."""
    sanitized_input = sanitize_input(user_input)
    encrypted_message = encrypt_message(sanitized_input)
    logging.info(f"User: {encrypted_message}")
    
    if any(word in sanitized_input.lower() for word in suspicious_keywords):
        alert = f"[ALERT] Suspicious activity detected: {sanitized_input}"
        encrypted_alert = encrypt_message(alert)
        logging.warning(encrypted_alert)
        print(alert)
        send_alert_email(alert)

def chatbot():
    """Simple chatbot that logs, monitors, and secures input."""
    authenticate_user()
    print("Chatbot initialized. Type 'exit' to stop.")
    while True:
        user_input = input("You: ")
        if user_input.lower() == "exit":
            print("Chatbot shutting down.")
            break
        monitor_chat(user_input)
        print("Chatbot: Message received.")

if __name__ == "__main__":
    chatbot()
