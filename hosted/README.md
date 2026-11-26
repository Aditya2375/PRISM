# Hosted review copy (demo data only)

A throwaway copy of the PRISM web console for reviewing the design in a browser. It is not a production setup.

* `python -m hosted.run` creates fresh demo data in a temporary directory on every start (Asha, her limited phone,
  Ravi, three files, a lost phone and the alerts it causes), runs the PRISM service and the local user backend on
  loopback only, and serves the console on `$PORT`.
* `hosted/proxy.py` is the only public surface. It forwards an allow-list of paths, limits each client address
  (120 requests per minute, and a lower limit on rejected tokens), and caps request bodies at 64 KB, so uploads in this copy
  are small.
* Two random tokens are printed once to the log at start: the operator token and the session token (the session
  token acts as Asha, an admin, on demo data). Share them only with the reviewer. They change on every restart.
* On a free host the service sleeps when idle and its disk is wiped on restart, so data and tokens reset.
* `web-p3/hosted-dist` is the console built with `VITE_PRISM_SAME_ORIGIN=1`, so it calls the page's own address.
  Rebuild it with `cd web-p3 && VITE_PRISM_SAME_ORIGIN=1 npx vite build --outDir hosted-dist --emptyOutDir`.
* Limits: sync between nodes and the extra cluster processes are not part of this copy. Plain demo only.
