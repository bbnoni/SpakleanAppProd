import requests

MAILJET_API_KEY = '14457ec97ed4c8e4085afaa588501405'
MAILJET_SECRET_KEY = '7b173043991ac2523e7753a4f970c815'

def send_mailjet_email(recipient_email, subject, content):
    url = "https://api.mailjet.com/v3.1/send"
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {MAILJET_API_KEY}:{MAILJET_SECRET_KEY}'
    }
    
    data = {
        "Messages": [
            {
                "From": {
                    "Email": "no-reply@spalean.com",
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
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200 or response.status_code == 201:
            print(f"Email sent to {recipient_email}")
        else:
            print(f"Failed to send email: {response.text}")
    except Exception as e:
        print(f"Error sending email: {e}")
