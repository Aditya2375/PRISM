# PRISM web console

A small React and Vite app for the PRISM API. Two views: an operator console (alerts with device, user, node and event, devices, files, the hash-chained audit log with "Verify chain") and a device-holder view (files, upload, devices, report lost, enrol a device).

It is a client of the existing HTTP API. It holds no keys: the operator view sends the operator token, and file work goes through the local backend `python -m kig.webapi`, which keeps the device key on your machine. Tokens live in memory only and the session ends after 15 idle minutes.

## Run for the demo

From the repository root, with the Python requirements installed and Node 20 or newer:

    bash web/run_demo.sh

It starts the service, the local backend and this app, creates demo data (a lost phone and the alerts it causes) and prints the address and both tokens.

## Develop

    cd web && npm ci && npm run build && npm test && npm run lint

## Honest limits

The "Verify chain" button shows the service checking itself. For independent proof use `verifier/prism_verify.py`. The UI cannot tell you the service is honest.

## Provenance

See NOTICE. The design, CSS and logo are original to this project.
