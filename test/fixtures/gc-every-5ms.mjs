// #3362 (test/http.test.mjs): preloaded into dist/http.js with --expose-gc, so that an object Node holds only weakly is
// collected at once. Production's heap is small (Dockerfile.http --max-old-space-size=104), so collections are frequent;
// this makes the weakly held clone of a 2025-era request (the SDK's legacy teardown follows its signal) go every time.
setInterval(() => globalThis.gc(), 5).unref();
