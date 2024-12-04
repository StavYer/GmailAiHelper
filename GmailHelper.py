import os
import gpt4all
import redis

import pickle
import json
import matplotlib.pyplot as plt
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


from dotenv import load_dotenv

load_dotenv()

MODEL_LOCATION = os.getenv("MODEL_LOCATION")

# Initialize the GPT4All model
model = gpt4all.GPT4All(MODEL_LOCATION) 

# Connect to Redis
r = redis.Redis(host='localhost', port=6379, db=0)

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Functions for caching
def get_cached_response(key):
    return r.get(key)

def set_cached_response(key, value, expiration=14400):
    r.setex(key, expiration, value)

def main():
    """Shows basic usage of the Gmail API."""
    creds = None  # Initialize credentials variable
    # Check if token.pickle file exists (contains saved user credentials)
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)  # Load credentials from file

    # If there are no valid credentials available, prompt the user to log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  # Refresh the credentials if they are expired
        else:
            # Start a new OAuth2 flow to get new credentials
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the new credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    # Build the Gmail service using the credentials
    service = build('gmail', 'v1', credentials=creds)
    # Call the Gmail API to list messages for the authenticated user, limiting to 1 message
    results = service.users().messages().list(userId='me', maxResults=20).execute()
    messages = results.get('messages', [])  # Extract messages from the results

    # Check if any messages were found
    if not messages:
        print('No messages found.')

    with model.chat_session():
        email_data = []

        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            headers = {header['name']: header['value'] for header in msg['payload']['headers']}  # Create a dictionary of headers
            subject = ''  # Initialize subject variable
            sender = ''  # Initialize sender variable

            subject = headers.get('Subject', '')

            sender = headers.get('From', '')

            cache_key = f"email_response:{message['id']}"
            cached_response = get_cached_response(cache_key)

            if cached_response:
                response_json = json.loads(cached_response)
            else:
                # Prepare the prompt
                prompt = f"""
                You are an AI assistant that categorizes emails.
                Email Subject: {subject}
                Email Sender: {sender}
                Please categorize this email into one of the following categories: Work, School, Shopping, Social, Updates, Promotions, Spam, or Other.
                Also, determine the priority of the email: Urgent, Important, Normal, Low.
                Does this email require a response? Answer Yes or No.
                output only raw JSON code, no explanations. 
                Provide your response in the following JSON format:
                {{
                "subject": "<subject>",
                "sender": "<sender>",
                "category": "<category>",
                "priority": "<priority>",
                "requires_response": "<Yes/No>"
                }}
                """

                # Get the LLM's response
                response = model.generate(prompt)
                # Parse the response
                try:
                    response_json = json.loads(response)
                    set_cached_response(cache_key, json.dumps(response_json))
                except json.JSONDecodeError:
                    print(response)
                    print("Failed to parse LLM response.")
                    continue
            email_data.append(response_json)

        # Analyze categories
        categories = [email['category'] for email in email_data]
        category_counts = {}
        for category in categories:
            category_counts[category] = category_counts.get(category, 0) + 1

        # Create pie chart
        labels = category_counts.keys()
        sizes = category_counts.values()

        plt.figure(figsize=(8,8))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%')
        plt.title('Email Categories')
        plt.show()


if __name__ == '__main__':
    main()
