from __future__ import print_function
import httplib2
import os
import time
import argparse
import logging

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

SCOPES = ['https://mail.google.com/',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/gmail.labels',
          'https://www.googleapis.com/auth/gmail.settings.basic']
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'DebouncedInbox APP'
LABEL_NAME = 'debouncer'
CRITERIA = {'from': '(-me)', 'sizeComparison': 'larger', 'size': 1}
LABEL_IDS = ['UNREAD', 'INBOX']
CREDENTIALS_FILE = 'debouncer_credentials.json'

def log(func):
    def wrapper(*args, **kwargs):
        logger.info('START:{}'.format(func.__name__))
        result = func(*args, **kwargs)
        logger.info('END:{}'.format(func.__name__))
        return result
    return wrapper

@log
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
        flags = tools.argparser.parse_args(args=[])
        credentials = tools.run_flow(flow, store, flags)
        logger.info('Storing credentials to ' + credential_path)
    return credentials

@log
def build_service():
    credentials = get_credentials()
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    return service

@log
def find_label(service):
    result = service.users().labels().list(userId='me').execute()
    labels = result['labels']
    label = next((l for l in labels if l['name'] == LABEL_NAME), None)
    if label is not None:
        return label['id']
    else:
        return None

@log
def create_label(service):
    body = {'name': LABEL_NAME,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'}
    result = service.users().labels().create(userId='me', body=body).execute()
    return result['id']

@log
def find_filter(service):
    result = service.users().settings().filters().list(userId='me').execute()
    if len(result) == 0:
        return None
    filters = result['filter']
    logger.info(filters)
    for f in filters:
        exists = (f['action']['removeLabelIds'] == LABEL_IDS and
                  f['criteria'] == CRITERIA)
        if exists:
            return f['id']
    return None

@log
def create_filter(labelId, service):
    body = {'criteria': CRITERIA,
            'action': {'removeLabelIds': LABEL_IDS,
                       'addLabelIds': [labelId]}}
    result = service.users().settings().filters().create(userId='me', body=body).execute()
    return result['id']

@log
def authorize():
    logger.info('logging in to gmail')
    service = build_service()

    logger.info('checking special label in gmail')
    label_id = find_label(service)
    if label_id is None:
        logger.info('no special label found, creating one')
        label_id = create_label(service)
        logger.info('special label created')
    logger.info('special label exists, moving on')

    logger.info('checking special filter exists')
    if find_filter(service) is None:
        logger.info('no special filter found, creating one')
        create_filter(label_id, service)
        logger.info('special filter created')
    logger.info('special filter found, moving on')
    logger.info('user setup complete')

@log
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

@log
def run(delay):
    logger.info('running debouncer with delay: {}'.format(delay))
    debounced_messages = 0
    while True:
        logger.info('searching for debounced messages')
        service = build_service()
        label_id = find_label(service)
        messages = messages_for_label(label_id, service)
        body = {'addLabelIds': LABEL_IDS,
                'removeLabelIds': [label_id]}
        messages_count = len(messages)
        if (debounced_messages != messages_count): # debounce to next cycle
            logger.info('debouncing to the next cycle with prev counter: {}, switching to next counter: {}'.format(debounced_messages,
                                                                                                             messages_count))
            debounced_messages = messages_count
        else: # no new messages, time to move everything to inbox
            logger.info('moving {} messages to inbox'.format(messages_count))
            for m in messages:
                id = m['id']
                service.users().messages().modify(userId='me',
                                                  id=id,
                                                  body=body).execute()
            logger.info('moved {} messages to inbox'.format(len(messages)))
            debounced_messages = 0
        logger.info('sleeping for {}'.format(delay))
        time.sleep(delay)

def main(args):
    if args.auth:
        authorize()
    else:
        run(args.delay)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DebouncedInbox')
    parser.add_argument('-a', '--auth', nargs='?', const=True, default=False)
    parser.add_argument('-d', '--delay', default=300, type=int, help='delay between debounced email checks in seconds')
    args = parser.parse_args()
    main(args)