# how to run debouncer

1. git clone git@github.com:neverov/debouncer.git
2. chmod +x scripts/*
3. cd debouncer
4. authorize: `./scripts/authorize`
5. run in background: `./scripts/run_local` – will create a `debouncer.log` and `pid` files to store logs and `nohup` pid respectively
6. stop: `./scripts/stop_local`