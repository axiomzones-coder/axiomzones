/* ══════════════════════════════════════════════
   Axiom Zones — Service Worker
   يُرفع في جذر المستودع (بجانب الملف الرئيسي)
   إستراتيجية: Network-first للصفحات، Cache-first للأصول الثابتة
   لا يكسر الموقع أبداً حتى لو فشل التخزين المؤقت لأي سبب
══════════════════════════════════════════════ */

var CACHE_NAME = 'axiomzones-v1';

/* أهم الصفحات لتخزينها مسبقاً — كل رابط يُحاول بشكل مستقل
   فلو فشل أحدها (مثلاً منصة لم تُنشر بعد) لا يوقف البقية */
var PRECACHE_URLS = [
  '/',
  '/kashf',
  '/prism',
  '/dar',
  '/aqar',
  '/uniuber',
  '/manifest.json'
];

self.addEventListener('install', function(event) {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return Promise.all(
        PRECACHE_URLS.map(function(url) {
          return cache.add(url).catch(function() {
            /* تجاهل أي رابط فشل تخزينه بدل إفشال التثبيت كاملاً */
          });
        })
      );
    })
  );
});

self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.map(function(key) {
          if (key !== CACHE_NAME) return caches.delete(key);
        })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', function(event) {
  var req = event.request;

  /* تجاهل أي طلب ليس GET (POST لـ /api/owner-login مثلاً يجب أن يمر مباشرة للسيرفر) */
  if (req.method !== 'GET') return;

  /* تجاهل طلبات لوحة التحكم والـ API — يجب أن تصل السيرفر دائماً، بدون كاش */
  var url = new URL(req.url);
  if (url.pathname.indexOf('/api/') === 0) return;

  /* التنقل بين الصفحات (فتح رابط / تحديث الصفحة): Network-first
     يحاول الإنترنت أولاً، ولو فشل (بدون نت) يرجع للنسخة المخزنة */
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then(function(res) {
          var resClone = res.clone();
          caches.open(CACHE_NAME).then(function(cache) { cache.put(req, resClone); });
          return res;
        })
        .catch(function() {
          return caches.match(req).then(function(cached) {
            return cached || caches.match('/');
          });
        })
    );
    return;
  }

  /* أصول ثابتة (صور، خطوط، CSS، JS من نفس المصدر أو CDN): Cache-first
     أسرع للمستخدم، ويُحدَّث الكاش في الخلفية دون انتظار */
  event.respondWith(
    caches.match(req).then(function(cached) {
      var fetchPromise = fetch(req).then(function(res) {
        if (res && res.status === 200) {
          var resClone = res.clone();
          caches.open(CACHE_NAME).then(function(cache) { cache.put(req, resClone); });
        }
        return res;
      }).catch(function() { return cached; });
      return cached || fetchPromise;
    })
  );
});

/* ══ Push Notifications — تنبيهات انخفاض الفوائد (من نسخة محمد الأصلية) ══ */
self.addEventListener('push', function(e) {
  if (!e.data) return;
  var data = e.data.json();
  e.waitUntil(
    self.registration.showNotification(data.title || 'Axiom Zones', {
      body:    data.body || 'انخفضت فوائد السوق — تحقق الآن',
      icon:    '/icons/icon-192.png',
      badge:   '/icons/icon-192.png',
      tag:     'loan-alert',
      vibrate: [200, 100, 200],
      data:    { url: data.url || '/kashf' },
      actions: [
        { action: 'open',    title: 'افتح كشف', icon: '/icons/icon-192.png' },
        { action: 'dismiss', title: 'لاحقاً' }
      ]
    })
  );
});

self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  if (e.action === 'dismiss') return;
  var url = (e.notification.data && e.notification.data.url) || '/kashf';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(function(clientList) {
        for (var i = 0; i < clientList.length; i++) {
          if ('focus' in clientList[i]) return clientList[i].focus();
        }
        if (clients.openWindow) return clients.openWindow(url);
      })
  );
});
