import requests
from requests.auth import HTTPBasicAuth

# Mailjet API Keys
MAILJET_API_KEY = '7b173043991ac2523e7753a4f970c815'
MAILJET_SECRET_KEY = '14457ec97ed4c8e4085afaa588501405'

def send_mailjet_email(recipient_email, subject, content):
    url = "https://api.mailjet.com/v3.1/send"

    # Email content data
    data = {
        "Messages": [
            {
                "From": {
                    "Email": "benoni.okaikoi@gmail.com",
                    "Name": "Spaklean"
                },
                "To": [
                    {
                        "Email": recipient_email,
                        "Name": "User"
                    }
                ],
                "Subject": subject,
                "TextPart": content,
            }
        ]
    }

    try:
        # Send request using Basic Auth
        response = requests.post(
            url,
            auth=HTTPBasicAuth(MAILJET_API_KEY, MAILJET_SECRET_KEY),  # Correct way to authenticate
            json=data
        )
        
        # Check the response
        if response.status_code in [200, 201]:
            print(f"Email sent to {recipient_email}")
        else:
            print(f"Failed to send email: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"Error sending email: {e}")

# Example usage
#send_mailjet_email("benoni.okaikoi@gmail.com", "Test Subject", "This is a test email.")
