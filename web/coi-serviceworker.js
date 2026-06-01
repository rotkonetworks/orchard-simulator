/*! coi-serviceworker v0.1.7 - https://github.com/gzuidhof/coi-serviceworker
 * MIT License, Copyright (c) 2021 Guido Zuidhof and contributors
 *
 * Vendored unmodified here so the parallel-WASM build runs on
 * GitHub Pages and other static hosts that cannot send
 * Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy headers
 * server-side. The service worker installs itself on first load,
 * reloads the page once, and from then on intercepts every same-
 * origin fetch and adds the headers to the response so the browser
 * enables `SharedArrayBuffer`.
 *
 * If the page is already cross-origin isolated (e.g. on
 * www.rotko.net behind nginx with the headers configured), this
 * script is a no-op.
 */

/* eslint-env serviceworker */

let coepCredentialless = false;
if (typeof window === 'undefined') {
  self.addEventListener('install', () => self.skipWaiting());
  self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

  self.addEventListener('message', (ev) => {
    if (!ev.data) return;
    if (ev.data.type === 'deregister') {
      self.registration
        .unregister()
        .then(() => self.clients.matchAll())
        .then((clients) => clients.forEach((client) => client.navigate(client.url)));
    } else if (ev.data.type === 'coepCredentialless') {
      coepCredentialless = ev.data.value;
    }
  });

  self.addEventListener('fetch', function (event) {
    const r = event.request;
    if (r.cache === 'only-if-cached' && r.mode !== 'same-origin') return;
    const request = coepCredentialless && r.mode === 'no-cors'
      ? new Request(r, { credentials: 'omit' })
      : r;
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.status === 0) return response;
          const newHeaders = new Headers(response.headers);
          newHeaders.set('Cross-Origin-Embedder-Policy', coepCredentialless ? 'credentialless' : 'require-corp');
          if (!coepCredentialless) newHeaders.set('Cross-Origin-Resource-Policy', 'cross-origin');
          newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders,
          });
        })
        .catch((e) => console.error(e)),
    );
  });
} else {
  (() => {
    if (window.crossOriginIsolated !== false) return;
    if (!window.isSecureContext) {
      console.warn('COOP/COEP Service Worker not installed: insecure context');
      return;
    }
    if (!('serviceWorker' in navigator)) {
      console.warn('COOP/COEP Service Worker not installed: navigator.serviceWorker not available');
      return;
    }
    navigator.serviceWorker
      .register(window.document.currentScript.src)
      .then((registration) => {
        if (registration.active && !navigator.serviceWorker.controller) {
          window.location.reload();
        }
      })
      .catch((err) => console.error('COOP/COEP Service Worker registration failed:', err));
  })();
}
