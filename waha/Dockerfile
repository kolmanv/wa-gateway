FROM devlikeapro/waha:chrome-2026.9.2@sha256:d4c2b1da8373fa48c5022aa947c95a87480cf6e26a9d3c9b59721f96b044d223
# whatsapp-web.js pins the build by intercepting the page's request for web.whatsapp.com, but after login
# WhatsApp Web's service worker serves that request itself, so the pin lapsed to the latest build.
# Make the page bypass the service worker; the build fails if the anchor line ever moves.
RUN f=/app/node_modules/whatsapp-web.js/src/Client.js \
 && grep -q 'await this.pupPage.setRequestInterception(true);' $f \
 && sed -i 's/await this.pupPage.setRequestInterception(true);/await this.pupPage.setBypassServiceWorker(true);\n            &/' $f \
 && grep -q 'setBypassServiceWorker(true)' $f
