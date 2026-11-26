# Hosted review copy (demo data only)

A throwaway copy of the PRISM web console for reviewing the design in a browser. It is not a production setup.

* `python -m hosted.run` creates fresh demo data in a temporary directory on every start (Asha, her limited phone,
  Ravi, three files, a lost phone and the alerts it causes), runs the PRISM service and the local user backend on
  loopback only, and serves the console on `$PORT`.
* `hosted/proxy.py` is the only public surface. It forwards an allow-list of paths, limits each client address
  (120 requests per minute, and a lower limit on rejected tokens), and caps request bodies at 64 KB. The console says so and
  refuses files over 40 KB here (base64 adds a third; the local app takes 4 MB). `/healthz` answers 200 only when both
  backends answer and 503 otherwise (cached for 3 s).
* Two random tokens are printed once to the log at start: the operator token and the session token (the session
  token acts as Asha, an admin, on demo data). Share them only with the reviewer. They change on every restart.
* On a free host the service sleeps when idle and its disk is wiped on restart, so data and tokens reset.
* `web-p3/hosted-dist` is the console built with `VITE_PRISM_SAME_ORIGIN=1`, so it calls the page's own address.
  Rebuild it with `cd web-p3 && VITE_PRISM_SAME_ORIGIN=1 npx vite build --outDir hosted-dist --emptyOutDir`.
* Limits: sync between nodes and the extra cluster processes are not part of this copy. Plain demo only.
* Treat the host log as a secret: the two tokens are printed there in plain text. To rotate them, restart the service.
* Behind a host that sets X-Forwarded-For (Render), set `HOSTED_TRUST_PROXY=1` (render.yaml does). Without it the limits use the
  peer address only, so a client cannot dodge them by sending its own header. There are also global limits (3000 requests and 100
  rejected-token replies per minute in total, charged only after the per-client limit passes, so one client cannot use them up alone;
  several distinct addresses together still can), a 10 s body read timeout, a 2 MB cap on backend replies, and uvicorn keep-alive 5 s.
  There is no connection cap and no header-read timeout in this process (a cap let partial-header sockets lock everyone out), so slow-header
  attacks are left to the host's edge proxy; Render's does that. Checked on the live host after deploy.
* Header size is not capped by this process (a 20 KB header gets through to the proxy); the host's edge limits it.
* The demo service signs with a key that is generated at start and kept unencrypted in the temporary data directory (no
  passphrase), and the two tokens are printed to the host log. That is acceptable for throwaway demo data and not for a real
  deployment, where the key is sealed with a passphrase or a hardware keystore and tokens are never logged.
* `python scripts/smoke.py URL --operator-token T --session-token S` checks a running copy.
