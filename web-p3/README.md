# PRISM web console, red design (web-p3)

A React and Vite console for the PRISM API in the red-and-black design supplied by Abhishek (landing, selection, login and the admin shell: sidebar, cards, tables, pills). Every number and row on screen comes from the real service. There is no sample data, no sign-up (the service has no accounts with passwords) and no local storage.

Two views: an **operator console** (overview, devices, files and keys, alerts with device, user, node, event and source, the hash-chained audit log with "Verify chain", limits) and a **device-holder view** (files with upload, download and delete, devices with report lost, enrol a device with fingerprint compare, activity, limits). The device-holder view talks to `python -m kig.webapi`, which keeps the device key on your machine.

## Run for the demo

From the repository root, with the Python requirements installed and Node 20 or newer:

    bash web-p3/run_demo.sh

It starts the service, the local backend and this app, seeds a lost-phone story and prints the address (http://localhost:4173) and both tokens. Paste the operator token for the Operator console, the session token for Device holder.

## Develop

    cd web-p3 && npm ci && npm run build && npm test && npm run lint

## What is and is not claimed

- The idle logout counts pointer and key activity only. After 15 idle minutes a timer forgets the token.
- "Verify chain" is the service checking its own log. For independent proof use `verifier/prism_verify.py`.
- The service and `vite preview` send no X-Frame-Options header. A meta CSP cannot set `frame-ancestors`. Put a proxy with `X-Frame-Options: DENY` in front for any real deployment.
- CSP `connect-src` is fixed in `index.html` to `127.0.0.1` and `localhost` on ports 8443 and 8788.
- Detection is rule based, recall 0.83 on our own scenarios. See the main README for the measured numbers and limits.

## Credits

The visual design, page layout, images (`public/images`) and the CSS of the landing, selection, login and admin shell come from the front end by Abhishek (team "Do You Care"). The application logic (token sign-in, API client, idle timer, all pages and their data) was rewritten for this repository. See NOTICE.
