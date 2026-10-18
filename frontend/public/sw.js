// Service Worker for Soroban Identity PWA
// Handles offline caching and sync

const CACHE_VERSION = 'v2';
const CACHE_NAME = `soroban-identity-${CACHE_VERSION}`;
const STATIC_CACHE_NAME = `soroban-identity-static-${CACHE_VERSION}`;
const API_CACHE_NAME = `soroban-identity-api-${CACHE_VERSION}`;
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/vite-env.d.ts',
];

// TTLs per data type (milliseconds) - aligned with L2/L3 cache policies
const CACHE_TTLS = {
  static: 7 * 24 * 60 * 60 * 1000, // 7 days for static assets
  api: 5 * 60 * 1000, // 5 minutes for API responses
  public: 60 * 60 * 1000, // 1 hour for public data
};

// Cache hit rate monitoring counters
const cacheStats = {
  hits: 0,
  misses: 0,
  revalidations: 0,
};

function recordCacheHit() {
  cacheStats.hits += 1;
}

function recordCacheMiss() {
  cacheStats.misses += 1;
}

function recordRevalidation() {
  cacheStats.revalidations += 1;
}

function getCacheHitRate() {
  const total = cacheStats.hits + cacheStats.misses;
  return total === 0 ? 0 : cacheStats.hits / total;
}

// Store a response with a timestamp header for TTL-based expiry
async function putWithTimestamp(cacheName, request, response) {
  const headers = new Headers(response.headers);
  headers.set('x-sw-cached-at', Date.now().toString());
  const body = await response.clone().blob();
  const cachedResponse = new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
  const cache = await caches.open(cacheName);
  await cache.put(request, cachedResponse);
}

// Check whether a cached response has exceeded its TTL
function isExpired(response, ttl) {
  const cachedAt = response.headers.get('x-sw-cached-at');
  if (!cachedAt) {
    return true;
  }
  return Date.now() - parseInt(cachedAt, 10) > ttl;
}

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((error) => {
        console.warn('Failed to cache some static assets:', error);
      });
    })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  const currentCaches = [CACHE_NAME, STATIC_CACHE_NAME, API_CACHE_NAME];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (!currentCaches.includes(cacheName)) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event - serve from cache, fall back to network
self.addEventListener('fetch', (event) => {
  // Skip cross-origin requests and non-GET methods
  if (
    !event.request.url.startsWith(self.location.origin) ||
    event.request.method !== 'GET'
  ) {
    return;
  }

  // Network first strategy for API calls (with cache fallback)
  if (event.request.url.includes('/api/')) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          // Cache successful responses with TTL metadata
          if (response && response.status === 200) {
            putWithTimestamp(API_CACHE_NAME, event.request, response).catch((error) => {
              console.warn('Failed to cache API response:', error);
            });
          }
          return response;
        })
        .catch(async () => {
          // Fall back to cache when offline
          const cached = await caches.match(event.request);
          if (cached) {
            recordCacheHit();
            return cached;
          }
          recordCacheMiss();
          return new Response(
            JSON.stringify({ error: 'Offline - no cached response available' }),
            {
              status: 503,
              statusText: 'Service Unavailable',
              headers: new Headers({ 'Content-Type': 'application/json' }),
            }
          );
        })
    );
    return;
  }

  // Stale-while-revalidate strategy for static assets
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      const networkFetch = fetch(event.request)
        .then((response) => {
          // Cache new static assets with TTL metadata
          if (response && response.status === 200) {
            putWithTimestamp(STATIC_CACHE_NAME, event.request, response).catch((error) => {
              console.warn('Failed to cache static asset:', error);
            });
          }
          return response;
        })
        .catch(() => {
          // Return offline page if available
          return caches.match('/offline.html').catch(() => {
            return new Response('Offline - Unable to load', {
              status: 503,
              statusText: 'Service Unavailable',
              headers: new Headers({
                'Content-Type': 'text/plain',
              }),
            });
          });
        });

      if (cachedResponse) {
        recordCacheHit();
        // Serve stale content immediately, revalidate in background
        if (isExpired(cachedResponse, CACHE_TTLS.static)) {
          recordRevalidation();
          event.waitUntil(networkFetch.catch(() => undefined));
        } else {
          event.waitUntil(networkFetch.catch(() => undefined));
        }
        return cachedResponse;
      }

      recordCacheMiss();
      return networkFetch;
    })
  );
});

// Background sync for offline data
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-credentials') {
    event.waitUntil(
      syncCredentials().catch((error) => {
        console.error('Background sync failed:', error);
      })
    );
  }
});

async function syncCredentials() {
  try {
    // Get pending operations from IndexedDB
    const db = await openDB();
    const pendingOps = await getPendingOperations(db);

    if (pendingOps.length === 0) {
      return;
    }

    // Retry failed operations
    for (const op of pendingOps) {
      try {
        await fetch(op.url, {
          method: op.method,
          headers: op.headers,
          body: op.body ? JSON.stringify(op.body) : undefined,
        });

        // Remove successful operation from queue
        await removePendingOperation(db, op.id);
      } catch (error) {
        console.error(`Failed to sync operation ${op.id}:`, error);
      }
    }

    // Notify clients that sync is complete
    const clients = await self.clients.matchAll();
    clients.forEach((client) => {
      client.postMessage({
        type: 'SYNC_COMPLETE',
        count: pendingOps.length,
      });
    });
  } catch (error) {
    console.error('Sync failed:', error);
    throw error;
  }
}

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('soroban-identity', 2);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains('pending-operations')) {
        db.createObjectStore('pending-operations', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('credentials')) {
        db.createObjectStore('credentials', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('dids')) {
        db.createObjectStore('dids', { keyPath: 'id' });
      }
    };
  });
}

function getPendingOperations(db) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(['pending-operations'], 'readonly');
    const store = tx.objectStore('pending-operations');
    const request = store.getAll();

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

function removePendingOperation(db, id) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(['pending-operations'], 'readwrite');
    const store = tx.objectStore('pending-operations');
    const request = store.delete(id);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(null);
  });
}

// Push notifications for credential expiry
self.addEventListener('push', (event) => {
  let data = { title: 'Soroban Identity Alert', body: 'A credential status update has occurred.' };
  if (event.data) {
    try {
      data = event.data.json();
    } catch {
      data.body = event.data.text();
    }
  }

  const options = {
    body: data.body,
    icon: '/icon-192x192.png',
    badge: '/icon-96x96.png',
    data: data.url || '/',
    vibrate: [100, 50, 100],
  };

  event.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url === event.notification.data && 'focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(event.notification.data || '/');
      }
    })
  );
});

// Message handler for client communication
self.addEventListener('message', (event) => {
  if (!event.data) {
    return;
  }

  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }

  // Report cache hit rate monitoring stats to clients
  if (event.data.type === 'GET_CACHE_STATS') {
    event.source?.postMessage({
      type: 'CACHE_STATS',
      stats: {
        ...cacheStats,
        hitRate: getCacheHitRate(),
      },
    });
  }

  // Cache invalidation pipeline: purge a specific URL or all caches
  if (event.data.type === 'INVALIDATE_CACHE') {
    event.waitUntil(
      (async () => {
        if (event.data.url) {
          await Promise.all([
            caches.open(STATIC_CACHE_NAME).then((cache) => cache.delete(event.data.url)),
            caches.open(API_CACHE_NAME).then((cache) => cache.delete(event.data.url)),
          ]);
        } else {
          await Promise.all([
            caches.delete(STATIC_CACHE_NAME),
            caches.delete(API_CACHE_NAME),
          ]);
        }
        event.source?.postMessage({ type: 'CACHE_INVALIDATED', url: event.data.url || null });
      })()
    );
  }
});

