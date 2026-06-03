# Deploy: orchard.rotko.net

Static-site deploy for the orchard-simulator web demo onto the Rotko
edge servers (bkk06/07/08), serving as `orchard.rotko.net`.

## How it works

1. Every push to `main` triggers `.github/workflows/deploy.yml`,
   which builds both WASM variants and uploads a tarball as the
   `latest-site` GitHub release.
2. Each edge box runs `orchard-deploy.timer` every 2 minutes. The
   timer fires `orchard-deploy.service` which calls
   `install.sh`, comparing the local SHA against the release's
   advertised SHA and only downloading + unpacking when there's a
   change.
3. nginx serves the unpacked tree from `/var/www/orchard-rotko-net/`
   with `Cross-Origin-{Opener,Embedder}-Policy` headers so the
   parallel-WASM rayon path works.

## Per-edge-box setup (bkk06 / bkk07 / bkk08)

One-time:

```bash
# Install the pull script and systemd units.
sudo install -m 0755 install.sh /usr/local/bin/orchard-deploy-install
sudo install -m 0644 orchard-deploy.service /etc/systemd/system/
sudo install -m 0644 orchard-deploy.timer   /etc/systemd/system/

# Drop the nginx vhost into place. Adjust if haproxy is the TLS
# terminator and nginx is the origin.
sudo install -m 0644 orchard.rotko.net.nginx.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/orchard.rotko.net.nginx.conf \
            /etc/nginx/sites-enabled/orchard.rotko.net.conf

# Prepare the docroot.
sudo mkdir -p /var/www/orchard-rotko-net

# First pull.
sudo /usr/local/bin/orchard-deploy-install

# Enable the timer and reload nginx.
sudo systemctl daemon-reload
sudo systemctl enable --now orchard-deploy.timer
sudo nginx -t && sudo systemctl reload nginx
```

Check status:

```bash
systemctl list-timers | grep orchard-deploy
journalctl -u orchard-deploy.service -n 50 --no-pager
```

Force a redeploy:

```bash
sudo systemctl start orchard-deploy.service
```

## DNS

Two records at the rotko.net zone:

```
orchard   A      <bkk06 anycast IP>
orchard   AAAA   <bkk06 anycast IPv6 if applicable>
```

If you're using anycast across bkk06/07/08, point at the anycast IP
(see the project's `reference-rotko-anycast` memory). Otherwise add
a CNAME to whichever box terminates TLS for the site, or use
GeoDNS / round-robin per your standard.

## TLS

If haproxy terminates TLS the existing `smart-cert-renewal.sh`
pipeline issues + syncs the cert just like every other rotko site;
just add `orchard.rotko.net` to the certbot dn list.

If nginx terminates TLS directly, uncomment the `ssl_certificate`
lines in `orchard.rotko.net.nginx.conf` and add `orchard.rotko.net`
to whatever cert pipeline runs on the box.

## Rollback

Each deploy keeps the previous tree as
`/var/www/orchard-rotko-net.prev`. To revert:

```bash
sudo systemctl stop orchard-deploy.timer
sudo mv /var/www/orchard-rotko-net /var/www/orchard-rotko-net.broken
sudo mv /var/www/orchard-rotko-net.prev /var/www/orchard-rotko-net
sudo nginx -s reload
```

Then keep the timer disabled until the GH release is fixed (or pin
the install script to a specific tag by setting `ORCHARD_TAG`).

## Files

- `install.sh` — idempotent pull-and-unpack from the GH release
- `orchard-deploy.service` / `orchard-deploy.timer` — systemd unit
  pair driving the periodic pull
- `orchard.rotko.net.nginx.conf` — nginx vhost with COOP/COEP +
  CSP + cache control
