import os
import time
import flask
import json
import storage
import log
import services

from oauth2client import client
from oauth2client.client import OAuth2WebServerFlow
from werkzeug.exceptions import Unauthorized

CLIENT_ID = '540788823194-7cgtek0h29ta324fmg0ueugrcfloljpc.apps.googleusercontent.com'
CLIENT_SECRET = 'Ejk_XaZhI0Jvt60mrlvW4AQ5'
SCOPE = ['https://mail.google.com/',
         'https://www.googleapis.com/auth/userinfo.email',
         'https://www.googleapis.com/auth/gmail.readonly',
         'https://www.googleapis.com/auth/gmail.modify',
         'https://www.googleapis.com/auth/gmail.labels',
         'https://www.googleapis.com/auth/gmail.settings.basic']
APP_SECRET_KEY = 'VfedCzx,eT88kj7A33^K'

logger = log.build_logger(__name__)
app = flask.Flask(__name__)
conn = storage.connect(os.environ['DATABASE_URL'])
storage.migrate(conn)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = APP_SECRET_KEY
app.config['CONNECTION'] = conn
app.config['TIMER'] = services.start_timer(conn)

@app.route('/timer/start', methods=['POST'])
def start():
    conn = app.config['CONNECTION']
    user_id = flask.session['user_id']
    logger.info('starting timer for user: {}')
    storage.save_timer(conn, user_id, True)
    return flask.redirect(flask.url_for('index'))

@app.route('/timer/stop', methods=['POST'])
def stop():
    conn = app.config['CONNECTION']
    user_id = flask.session['user_id']
    logger.info('stopping timer for user: {}'.format(user_id))
    storage.save_timer(conn, user_id, False)
    return flask.redirect(flask.url_for('index'))

@app.route('/set-delay', methods=['POST'])
def set_delay():
    delay = flask.request.form['delay']
    conn = app.config['CONNECTION']
    user_id = flask.session['user_id']
    logger.info('setting user\'s timer to {}'.format(delay))
    storage.save_delay(conn, user_id, delay)
    return flask.redirect(flask.url_for('index'))

@app.route('/admin')
def admin():
    conn = app.config['CONNECTION']
    timers = storage.get_timers(conn)
    return flask.render_template('admin.html', timers=timers)

@app.route('/')
def index():
    if 'user_id' not in flask.session:
        logger.info('no credentials, redirecting to auth')
        return flask.redirect(flask.url_for('oauth2callback'))
    conn = app.config['CONNECTION']
    user_id = flask.session['user_id']
    credentials = services.credentials(conn, user_id)
    if credentials.access_token_expired:
        logger.info('token expired, redirecting to auth')
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
        logger.info('logged in user %s', user_id)
        services.authorize(user_id, credentials)
        timer = storage.get_timer(conn, user_id)
        return flask.render_template('index.html', name=user_id, enabled=timer['timer_enabled'], delay=timer['delay'])

@app.route('/oauth2callback')
def oauth2callback():
    flow = OAuth2WebServerFlow(client_id=CLIENT_ID,
                               client_secret=CLIENT_SECRET,
                               scope=SCOPE,
                               redirect_uri=flask.url_for('oauth2callback', _external=True),
                               access_type='offline',
                               approval_prompt='force')
    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        logger.info('received code from google auth: {}'.format(auth_code))
        credentials = flow.step2_exchange(auth_code)
        logger.info('received google credentials: {}'.format(credentials))
        user_id = json.loads(credentials.to_json()).get('id_token').get('email')
        conn = app.config['CONNECTION']
        storage.save_user(conn, user_id, credentials.to_json())
        flask.session['user_id'] = user_id
        return flask.redirect(flask.url_for('index'))

@app.route('/logout')
def logout():
    if 'user_id' not in flask.session:
        logger.info('no credentials, nothing to revoke')
        return 'ok'
    else:
        flask.session.pop('user_id')
        #credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
        #credentials.revoke(httplib2.Http())
        # TODO remove creds from session
        logger.info('credentials revoked')
        return 'ok'

@app.errorhandler(Unauthorized)
def handle_unauthorized(error):
    logger.info('Unauthorized happened, redirecting to auth')
    return flask.redirect(flask.url_for('oauth2callback'))

if __name__ == '__main__':
    app.run()