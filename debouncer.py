from __future__ import print_function
import httplib2
import os
import time
import argparse

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

SCOPES = ['https://mail.google.com/',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/gmail.labels',
          'https://www.googleapis.com/auth/gmail.settings.basic']
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'DebouncedInbox APP'
LABEL_NAME = 'debouncer'
CRITERIA = {'sizeComparison': 'larger', 'size': 1}
LABEL_IDS = ['UNREAD', 'INBOX']
CREDENTIALS_FILE = 'debouncer_credentials.json'

debounced_messages = 0

def get_credentials():
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir,
                                   CREDENTIALS_FILE)
    store = Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        if flags:
            credentials = tools.run_flow(flow, store, flags)
        else: # Needed only for compatibility with Python 2.6
            credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials

def build_service():
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    return discovery.build('gmail', 'v1', http=http)

def find_label(service):
    result = service.users().labels().list(userId='me').execute()
    labels = result['labels']
    label = next((l for l in labels if l['name'] == LABEL_NAME), None)
    if label is not None:
        return label['id']
    else:
        return None

def create_label(service):
    body = {'name': LABEL_NAME,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'}
    result = service.users().labels().create(userId='me', body=body).execute()
    return result['id']

def find_filter(service):
    result = service.users().settings().filters().list(userId='me').execute()
    if len(result) == 0:
        return None
    filters = result['filter']
    for f in filters:
        exists = (f['action']['removeLabelIds'] == LABEL_IDS and
                  f['criteria'] == CRITERIA)
        if exists:
            return f['id']
    return None

def create_filter(labelId, service):
    body = {'criteria': CRITERIA,
            'action': {'removeLabelIds': LABEL_IDS,
                       'addLabelIds': [labelId]}}
    result = service.users().settings().filters().create(userId='me', body=body).execute()
    return result['id']

def authorize():
    print('logging in to gmail')
    service = build_service()

    print('checking special label in gmail')
    label_id = find_label(service)
    if label_id is not None:
        print('no special label found, creating one')
        label_id = create_label(service)
        print('special label created')
    print('special label exists, moving on')

    print('checking special filter exists')
    if find_filter(service) is not None:
        print('no special filter found, creating one')
        create_filter(label_id, service)
        print('special filter created')
    print('special filter found, moving on')

    print('user setup complete')

def messages_for_label(label_id, service):
    response = service.users().messages().list(userId='me',
                                               labelIds=[label_id]).execute()
    messages = []
    if 'messages' in response:
        messages.extend(response['messages'])

    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        response = service.users().messages().list(userId=user_id,
                                                 labelIds=[label_id],
                                                 pageToken=page_token).execute()
        messages.extend(response['messages'])

    return messages

def run(delay):
    while True:
        print('searching for debounced messages')
        service = build_service()
        label_id = find_label(service)
        messages = messages_for_label(label_id, service)
        body = {'addLabelIds': LABEL_IDS,
                'removeLabelIds': [label_id]}
        if (debounced_messages != len(messages)):
            # debounce to next cycle
            debounced_messages = len(messages)
        else:
            # no new messages - time to move everything to inbox
            for m in messages:
                id = m['id']
                service.users().messages().modify(userId='me',
                                              id=id,
                                              body=body).execute()
            print('moved {} messages to inbox'.format(len(messages)))
        print('sleeping for {}'.format(delay))
        time.sleep(delay)

def main(args):
    if args.auth:
        authorize()
    else:
        delay = args.delay * 60 # to seconds
        run(delay)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'DebouncedInbox')
    parser.add_argument('-a', '--auth', nargs='?', const=True, default=False)
    parser.add_argument('-d', '--delay', default=5, help='delay between debounced email checks in minutes')
    args = parser.parse_args()
    main(args)