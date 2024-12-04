import os
import gpt4all

import pickle
import json
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


from dotenv import load_dotenv

load_dotenv()

MODEL_LOCATION = os.getenv("MODEL_LOCATION")

# Initialize the GPT4All model
model = gpt4all.GPT4All(MODEL_LOCATION) 

# If modifying these SCOPES, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

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
    results = service.users().messages().list(userId='me', maxResults=1).execute()
    messages = results.get('messages', [])  # Extract messages from the results

    # Check if any messages were found
    if not messages:
        print('No messages found.')
    else:
        for message in messages:
            # Get the full message details
            msg = service.users().messages().get(userId='me', id=message['id'], format='full').execute()
            headers = msg['payload']['headers']  # Extract headers from the message payload
            subject = ''  # Initialize subject variable
            sender = ''  # Initialize sender variable
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                if header['name'] == 'From':
                    sender = header['value']

            print(f"Subject: {subject}")
            print(f"From: {sender}")

if __name__ == '__main__':
    main()
