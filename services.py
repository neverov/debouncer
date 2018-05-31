import httplib2
import storage
import log
import datetime

from threading import Timer
from apiclient import discovery, errors
from oauth2client import client, tools
from oauth2client.client import OAuth2Credentials
from werkzeug.exceptions import Unauthorized

LABEL_NAME = 'debouncer'
CRITERIA = {'from': '(-me)', 'sizeComparison': 'larger', 'size': 1}
LABEL_IDS = ['INBOX']
TIMEOUT = 10.0

logger = log.build_logger(__name__)

@log.logfn(logger)
def build_service(credentials):
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    return service

@log.logfn(logger)
def find_label(user_id, service):
    result = service.users().labels().list(userId=user_id).execute()
    labels = result['labels']
    label = next((l for l in labels if l['name'] == LABEL_NAME), None)
    if label is not None:
        return label['id']
    else:
        return None

@log.logfn(logger)
def create_label(user_id, service):
    body = {'name': LABEL_NAME,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'}
    result = service.users().labels().create(userId=user_id, body=body).execute()
    return result['id']

@log.logfn(logger)
def find_filter(user_id, service):
    result = service.users().settings().filters().list(userId=user_id).execute()
    if len(result) == 0:
        return None
    filters = result['filter']
    for f in filters:
        exists = ('action' in f and
                  'removeLabelIds' in f['action'] and
                  f['action']['removeLabelIds'] == LABEL_IDS and
                  'criteria' in f and
                  f['criteria'] == CRITERIA)
        if exists:
            return f['id']
    return None

@log.logfn(logger)
def create_filter(user_id, labelId, service):
    body = {'criteria': CRITERIA,
            'action': {'removeLabelIds': LABEL_IDS,
                       'addLabelIds': [labelId]}}
    result = service.users().settings().filters().create(userId=user_id, body=body).execute()
    return result['id']

@log.logfn(logger)
def authorize(user_id, credentials):
    try:
        logger.info('logging in to gmail')
        service = build_service(credentials)

        logger.info('checking special label in gmail')
        label_id = find_label(user_id, service)
        if label_id is None:
            logger.info('no special label found, creating one')
            label_id = create_label(user_id, service)
            logger.info('special label created')
        logger.info('special label exists, moving on')

        logger.info('checking special filter exists')
        if find_filter(user_id, service) is None:
            logger.info('no special filter found, creating one')
            create_filter(user_id, label_id, service)
            logger.info('special filter created')
        logger.info('special filter found, moving on')
        logger.info('user setup complete')
    except errors.HttpError, error:
        logger.error('authorization error: %s', error)
        if error.resp.status == 401:
            print('authorization error: credentials revoked')
            raise RuntimeError('authorization error: credentials revoked')

@log.logfn(logger)
def messages_for_label(user_id, label_id, service):
    response = service.users().messages().list(userId=user_id,
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

@log.logfn(logger)
def start_timer(conn):
    logger.info('starting timer for debouncer')
    timer = Timer(TIMEOUT, run, [conn, start_timer])
    timer.daemon = True
    timer.start()
    return timer

@log.logfn(logger)
def run(conn, restart_fn):
    try:
        now = datetime.datetime.now()
        timers = storage.get_active_timers(conn)
        logger.info('received active timers: {}'.format(timers))
        for t in timers:
            debounced_messages = t['messages']
            user_id = t['user_id']
            logger.info('searching for messages for user: {}'.format(user_id))
            service = build_service(credentials(conn, user_id))
            label_id = find_label(user_id, service)
            messages = messages_for_label(user_id, label_id, service)
            messages_count = len(messages)
            if (debounced_messages != messages_count): # debounce to next cycle
                logger.info('debouncing: last counter: {}, next counter: {}'.format(debounced_messages,
                                                                                    messages_count))
                storage.save_run(conn, user_id, messages_count)
            else: # no new messages, time to move everything to inbox
                body = {'addLabelIds': LABEL_IDS,
                        'removeLabelIds': [label_id]}
                logger.info('moving {} messages to inbox'.format(messages_count))
                for m in messages:
                    # if message has been archived during debounce period, don't move it

                    id = m['id']
                    service.users().messages().modify(userId=user_id,
                                                      id=id,
                                                      body=body).execute()
                logger.info('moved {} messages to inbox'.format(len(messages)))
                storage.save_run(conn, user_id, 0)
            logger.info('run for user: {} completed'.format(user_id))
            logger.info('timer restarted')
    finally: # continue to run timer no matter what
        restart_fn(conn)

@log.logfn(logger)
def credentials(conn, user_id):
    db_creds = storage.get_credentials(conn, user_id)
    if db_creds is None:
        raise Unauthorized('failed to find credentials in db')
    return OAuth2Credentials.from_json(db_creds)