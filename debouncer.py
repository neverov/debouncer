import os
import time
import flask
import json
import storage
import log
import services

from oauth2client import client
from werkzeug.exceptions import Unauthorized

SCOPES = ['https://mail.google.com/',
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify',
          'https://www.googleapis.com/auth/gmail.labels',
          'https://www.googleapis.com/auth/gmail.settings.basic']
CLIENT_SECRET = 'client_secret.json'
APP_SECRET_KEY = 'VfedCzx,eT88kj7A33^K'

logger = log.build_logger(__name__)
app = flask.Flask(__name__)

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
    conn = app.config['CONNECTION']
    user_id = flask.session['user_id']
    timers = storage.get_timers(conn, user_id)
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
    flow = client.flow_from_clientsecrets(
        CLIENT_SECRET,
        scope=SCOPES,
        redirect_uri=flask.url_for('oauth2callback', _external=True))
    flow.params['access_type'] = 'offline'
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

def main():
    conn = storage.connect(os.environ['DATABASE_URL'])
    storage.migrate(conn)

    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = APP_SECRET_KEY
    app.config['CONNECTION'] = conn

    port = 5000
    logger.info('running web app on %s', port)
    app.run(port=port)

if __name__ == '__main__':
    main()