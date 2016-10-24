from __future__ import print_function
import httplib2
import os
import time
import argparse
import logging
import flask
import json
import pprint

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage
from threading import Timer

SCOPES = ['https://mail.google.com/',
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/gmail.labels',
          'https://www.googleapis.com/auth/gmail.settings.basic']
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'DebouncedInbox APP'
APP_SECRET_KEY = 'VfedCzx,eT88kj7A33^K'
LABEL_NAME = 'debouncer'
CRITERIA = {'from': '(-me)', 'sizeComparison': 'larger', 'size': 1}
LABEL_IDS = ['UNREAD', 'INBOX']
CREDENTIALS_FILE = 'debouncer_credentials.json'

app = flask.Flask(__name__)
app.secret_key = APP_SECRET_KEY

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

pp = pprint.PrettyPrinter(indent=2)

timers = {}

def log(func):
    def wrapper(*args, **kwargs):
        logger.info('START:{}'.format(func.__name__))
        result = func(*args, **kwargs)
        logger.info('END:{}'.format(func.__name__))
        return result
    return wrapper

@log
def build_service(credentials):
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
def authorize(credentials):
    logger.info('logging in to gmail')
    service = build_service(credentials)

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
def run(user, delay, credentials):
    logger.info('running debouncer for user: {}'.format(user))
    debounced_messages = timers[user]['messages']
    logger.info('searching for debounced messages')
    service = build_service(client.OAuth2Credentials.from_json(credentials))
    label_id = find_label(service)
    messages = messages_for_label(label_id, service)
    body = {'addLabelIds': LABEL_IDS,
            'removeLabelIds': [label_id]}
    messages_count = len(messages)
    if (debounced_messages != messages_count): # debounce to next cycle
        logger.info('debouncing to the next cycle with prev counter: {}, switching to next counter: {}'.format(debounced_messages,
                                                                                                         messages_count))
        timers[user]['messages'] = messages_count
    else: # no new messages, time to move everything to inbox
        logger.info('moving {} messages to inbox'.format(messages_count))
        for m in messages:
            id = m['id']
            service.users().messages().modify(userId='me',
                                              id=id,
                                              body=body).execute()
        logger.info('moved {} messages to inbox'.format(len(messages)))
        timers[user]['messages'] = 0
    logger.info('run for user: {} completed'.format(user))
    logger.info('restarting the timer')
    timer = Timer(float(delay), run, [user, delay, credentials])
    timer.start()
    timers[user]['timer'] = timer
    logger.info('timer restarted')

@app.route('/timer/start', methods=['POST'])
def start():
    email = flask.session.get('email')
    delay = flask.session.get('delay', 300)
    credentials = flask.session.get('credentials')
    logger.info('creating new timer for user: {} with delay: {}'.format(email, delay))
    timer = Timer(float(delay), run, [email, delay, credentials])
    timers.update({email: {'timer': timer, 'messages': 0}})
    logger.info('timer created, starting')
    timer.start()
    return flask.redirect(flask.url_for('index'))

@app.route('/timer/stop', methods=['POST'])
def stop():
    email = flask.session.get('email')
    logger.info('stopping timer for user: {}'.format(email))
    timer = timers.pop(email, None)['timer']
    if timer is not None:
        logger.info('timer is running, stopping')
        timer.cancel();
    else:
        logger.info('timer is stopped, no action required')
    logger.info('timer stopped')
    return flask.redirect(flask.url_for('index'))

@app.route('/set-delay', methods=['POST'])
def set_delay():
    delay = flask.request.form['delay']
    logger.info('setting user\'s timer to {}'.format(delay))
    flask.session['delay'] = delay
    return flask.redirect(flask.url_for('index'))

@app.route('/admin')
def admin():
    return flask.render_template('admin.html', timers=timers)

@app.route('/')
def index():
    if 'credentials' not in flask.session:
        logger.info('no credentials, redirecting to auth')
        return flask.redirect(flask.url_for('oauth2callback'))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        logger.info('token expired, redirecting to auth')
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
        email = flask.session['email']
        logger.info('logged in user %s', email)
        authorize(credentials)
        enabled = email in timers
        delay = flask.session.get('delay', 300)
        return flask.render_template('index.html', name=email, enabled=enabled, delay=delay)

@app.route('/oauth2callback')
def oauth2callback():
    flow = client.flow_from_clientsecrets(
        'client_secret.json',
        scope=SCOPES,
        redirect_uri=flask.url_for('oauth2callback', _external=True))
    flow.params['access_type'] = 'offline'
    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        flask.session['email'] = json.loads(credentials.to_json()).get('id_token').get('email')
        # TODO store creds in the database
        return flask.redirect(flask.url_for('index'))

def main():
    debug = True
    port = 5000
    logger.info('running web app on %s', port)
    app.run(port=port, debug=debug)

if __name__ == '__main__':
    main()