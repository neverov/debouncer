# Installation

If you don't have `pip` installed, run `sudo easy_install pip`.

1. git clone git@github.com:neverov/debouncer.git
2. cd debouncer
3. Install dependencies: `pip install -r requirements.txt`
4. chmod +x scripts/*

# Authorizing

In order to run debouncer you will have to authorize first:

1. run: `./scripts/authorize`
2. your browser will be opened and you should use you account to log in
3. after logging in close your browser
4. credentials file will be located at `~/.credentials/debouncer_credentials.json`

# Running

There are two options to run debouncer:

1. run in the console as a python scripts
2. run in background

## Running in the console

Run `python debouncer`.
To stop press CTRL-C.

## Running in background

Use `scripts/run_local` to start debouncer.
Use `scripts/stop_local` to stop debouncer.

# Logs

Logs are stored in `debouncer.log` file.