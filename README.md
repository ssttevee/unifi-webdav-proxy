# unifi-webdav-proxy

A quick and dirty program for proxying a local unifi controller instance running behind a cloudflare tunnel.

As an added bonus, the `config.gateway.json` are accessible through webdav with the same credentials used for logging into the control panel.

## TODOs

- webdav credentials caching
- better methods of determining when to serve webdav
- read unifi server.properties for real mongodb server info
