Looking at this task, I need to wire in cache manager and metering/billing functionality. However, the current file doesn't import these modules. Let me analyze what's needed:

1. Import cache manager, metering, and billing modules
2. Initialize cache manager with config and Redis client
3. Attach cache to request context
4. Use cache for DID resolution and query caching
5. Register cache stats/purge routes
6. Start warming scheduler
7. Wire metering middleware
8. Wire billing routes (usage dashboard, invoices)

Since the specific module files aren't shown, I'll need to make reasonable assumptions about their APIs based on the issue requirements. Let me implement this carefully while preserving all existing functionality.

```javascript
import { URL } from "node:url";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  appendAuditLog,
  readCredentials,
  writeCredentials,
  createAndPersistCredential,
  revokeAndPersistCredential,
  updateAndPersistCredential,
  DuplicateCredentialError,
  ConcurrencyConflictError,
} from "./storage.js";
import { findExpiringCredentials, paginate } from "./expiry.js";
import {
  setPaginationHeaders,
} from "./routes/pagination.js";
import {
  createWebhookRecord,
  deleteWebhookRecord,
  getWebhookRecord,
  readWebhookLogs,
  readWebhooks,
  WebhookDeliveryService,
} from "./webhooks.js";
import { startAccessLog } from "./access-log.js";
import { createDataLoaders } from "./dataloader.js";
import { executeGraphQL, renderGraphiQLPlayground } from "./graphql.js";
import {
  resolveApiVersion,
  setVersionHeaders,
  SUPPORTED_VERSIONS,
  DEFAULT_VERSION,
  DEPRECATED_VERSIONS,
} from "./versioning.js";
import {
  notFound,
  readJson,
  readRawBody,
  requireAdmin,
  requireAuth,
  sendFormatted,
  sendJson,
  sendText,
  setCorsHeaders,
  validateContentType,
} from "./http-utils.js";
import { KEY_ID_HEADER, NonceStore, verifySignedRequest } from "./request-signing.js";
import { createNonceStore, nonceMiddleware } from "./middleware/nonce.js";
import { normalizeCspReports, setSecurityHeaders } from "./security-headers.js";
import {
  CREDENTIAL_STATUS_TYPE,
  createVcSerializer,
  credentialStatus,
} from "./vc-jsonld.js";

/**
 * Whether the caller wants the W3C JSON-LD representation.
 *
 * Accept is the correct mechanism, but a browser address bar cannot set it,
 * so `?format=jsonld` is honoured as well.
 */
function wantsJsonLd(req, url) {
  if (url.searchParams.get("format") === "jsonld") return true;
  const accept = String(req.headers.accept ?? "");
  return accept.includes("application/ld+json");
}
import { sanitizeDidMetadata, schemas, validateRequest } from "./validation.js";
import {
  buildApiRootLinks,
  buildCredentialCollectionLinks,
  buildCredentialLinks,
  buildDidLinks,
  buildWebhookLinks,
  formatLinkHeader,
  resolveLinkPrefix,
} from "./hateoas.js";
import { routeLabel } from "./route-label.js";
import { requestContextStore } from "./request-context.js";
import { correlationMiddleware, handleTraceRoutes } from "./middleware/tracing.js";
import { cursorPage, offsetMeta, offsetPage, pageNumberMeta } from "./routes/pagination.js";
import { handleEventsRequest } from "./sse.js";
import { handleLongPollRequest } from "./long-poll.js";
import { logger } from "./logger.js";
import { AnalyticsService, detectCountry } from "./analytics.js";
import { createRateLimiter } from "./middleware/ratelimit.js";
import { ApiKeyService } from "./api-keys.js";
import { OAuthService } from "./oauth.js";
import { UsageTracker } from "./analytics/usage.js";
import { EmailTransport } from "./email.js";
import { pickQuotaBinding, QuotaTracker, notifyQuotaThresholdOwner } from "./quota.js";
import { DeprecationRegistry, notifyDeprecatedEndpointOwner } from "./deprecation.js";
import { DdosProtection, ddosResponse } from "./ddos-protection.js";
import { TenantRegistry, handleTenantRoutes, resolveTenantId } from "./tenancy/index.js";
import { openTelemetryHttpMiddleware } from "./tracing/index.js";
import { EventStore, EventReplayer, createEvent, EventTypes, handleEventSourcingRoutes } from "./events/index.js";
import { handleMockApiRequest } from "./mock-api.js";
import { collectHealth, collectReadiness } from "./health.js";
import { CacheManager, CACHE_TTL, cacheKey } from "./cache/index.js";
import { MeteringService, meteringMiddleware, handleBillingRoutes } from "./billing/index.js";
const SERVER_VERSION = "0.1.0";
const MIN_SDK_VERSION = "0.1.0";
const SERVER_FEATURES = [
  "webhook_delivery",
  "batch_issuance",
  "event_polling",
  "graphql_api",
  "api_versioning",
  "quota_tracking",
  "deprecation_warnings",
  "response_compression",
  "job_queue",
  "graceful_shutdown",
  "hateoas",
  "multi_layer_cache",
  "usage_metering",
  "billing",
];

const usageTracker = new UsageTracker();

export function createApp({
  config,
  soroban,
  metrics,
  metricsAggregator,
  analytics = new AnalyticsService(),
  didCache = null,
  // Health and readiness probes only need something that can answer PING;
  // the DID cache already owns a connected client, so reuse it unless a
  // caller (or a test) supplies one explicitly.
  redisClient = didCache?.client ?? null,
  webhookService = new WebhookDeliveryService(config),
  apiKeyService = new ApiKeyService(config),
  oauthService = new OAuthService(config),
  credentialIssueQueue = config.credentialIssueQueue ?? null,
  batchVerificationQueue = config.batchVerificationQueue ?? null,
  rateLimiter = null,
  accessLogSink = null,
  realtime = null,
  nonceStore = new NonceStore({ ttlSeconds: config.requestSigningMaxAgeSeconds }),
  replayNonceStore = null,
  vcSerializer = createVcSerializer(config, { logger }),
  emailTransport = new EmailTransport(config),
  quotaTracker = null,
  deprecationRegistry = null,
  ddosProtection = null,
  sessionKeyRegistry = null,
  cacheManager = null,
  meteringService = null,
}) {
  // Expose the key service on config so http-utils.requireAuth can validate
  // issued API keys instead of falling back to the single admin key.
  config.apiKeyService = apiKeyService;
  config.oauthService = oauthService;
  
  // Expose job queues on config for route handlers
  config.credentialIssueQueue = credentialIssueQueue;
  config.batchVerificationQueue = batchVerificationQueue;

  // One limiter per app instance, so its buckets live as long as the server
  // rather than being rebuilt per request.
  // #956: per-IP, per-user, endpoint and tier budgets with burst allowance
  // and premium bypass. A caller-supplied limiter only needs a check() method.
  const limiter = rateLimiter ?? createRateLimiter(config, { metrics });

  // One quota tracker per app instance (#748), independent of the rate
  // limiter above: it counts against calendar day/month budgets rather than
  // a rolling per-minute window.
  const quota =
    quotaTracker ??
    new QuotaTracker({
      overageMode: config.quotaOverageMode ?? "block",
      onThreshold: ({ apiKeyId, tier, period, threshold, used, limit }) => {
        metrics?.observeQuotaThreshold?.({ tier, period, threshold });
        logger.warn({ apiKeyId, tier, period, threshold, used, limit }, "API quota threshold reached");
        return notifyQuotaThresholdOwner({ config, apiKeyService, emailTransport, apiKeyId, tier, period, threshold, used, limit });
      },
    });

  const ddos =
    ddosProtection ??
    new DdosProtection(config, {
      onAlert: async (event) => {
        metrics?.observeDdosEvent?.(event.type);
        logger.warn(event, "DDoS protection event");
      },
    });

  // One deprecation registry per app instance (#751).
  const deprecation =
    deprecationRegistry ??
    new DeprecationRegistry({
      onUsage: ({ rule, req }) => {
        metrics?.observeDeprecatedEndpointUsage?.(rule.name);
        logger.warn({ endpoint: rule.name, apiKeyId: req.apiKeyId ?? null, path: req.url }, "Deprecated endpoint used");
        const apiKeyId = req.apiKeyId ?? req.auth?.apiKey?.id ?? null;
        if (!apiKeyId || !deprecation.shouldNotify(apiKeyId, rule.name)) return undefined;
        return notifyDeprecatedEndpointOwner({ config, apiKeyService, emailTransport, apiKeyId, rule });
      },
    });

  // Per-session AES-GCM key registry (#1049). Keys are generated per session,
  // rotated on demand, and never persisted: a restart simply invalidates the
  // sessions that were using them.
  const encryptionKeys =
    sessionKeyRegistry ??
    new SessionKeyRegistry({
      ttlSeconds: config.encryptionSessionKeyTtlSeconds,
      rotationSeconds: config.encryptionKeyRotationSeconds,
      maxKeys: config.encryptionMaxSessionKeys,
    });

  const tenantRegistry = new TenantRegistry(config);
  void tenantRegistry.init();

  // #1052: nonce-based replay prevention for sensitive (state-changing)
  // operations. Backed by Redis when available so nonces are shared across
  // instances; falls back to an in-process store otherwise.
  const replayStore =
    replayNonceStore ??
    createNonceStore({
      redisClient,
      ttlSeconds: config.nonceTtlSeconds ?? 300,
      metrics,
    });
  const checkNonce = nonceMiddleware({
    store: replayStore,
    ttlSeconds: config.nonceTtlSeconds ?? 300,
    metrics,
  });

  const eventStore = new EventStore({ dataDir: `${config.dataDir}/events` });
  void eventStore.init();
  const eventReplayer = new EventReplayer(eventStore);

  // #1118: multi-layer caching strategy. L1 is in-memory (LRU), L2 is Redis
  // when available, L3 is CDN via response headers. The manager owns the
  // warming scheduler and the invalidation pipeline.
  const cache =
    cacheManager ??
    new CacheManager({
      config,
      redisClient,
      metrics,
      logger,
    });
  // Start the warming scheduler (no-op when disabled in config).
  if (typeof cache.startWarming === "function") {
    try {
      cache.startWarming();
    } catch (error) {
      logger.warn({ error: error.message }, "Failed to start cache warming scheduler");
    }
  }

  // #1119: API usage metering and billing. The service tracks per-endpoint
  // calls, enforces quotas, and generates invoices. When no service is
  // supplied it is created from config so the routes always exist.
  const metering =
    meteringService ??
    new MeteringService({
      config,
      apiKeyService,
      emailTransport,
      logger,
      metrics,
    });
  const meter = meteringMiddleware({ service: metering, config });

  return async function app(req, res) {
    const startTime = Date.now();
    const url = new URL(
      req.url,
      `http://${req.headers.host ?? "localhost"}`,
    );

    // Resolve API version and normalized pathname
    const { version, normalizedPath, isExplicitUrlVersion, isDeprecated } = resolveApiVersion(req, url);
    const pathname = normalizedPath;

    // Set API Version and Deprecation response headers
    setVersionHeaders(res, { version, isDeprecated, isExplicitUrlVersion });

    // Instrument the request for the Prometheus HTTP metrics. `res.once`
    // fires whether the handler returned a response, threw, or the client
    // disconnected, so in-flight can never leak.
    if (metrics?.observeHttpRequest) {
      const startedAt = process.hrtime.bigint();
      metrics.httpInFlight?.inc();
      res.once("close", () => {
        metrics.httpInFlight?.dec();
        metrics.observeHttpRequest({
          method: req.method,
          route: routeLabel(pathname),
          statusCode: res.statusCode,
          durationSeconds: Number(process.hrtime.bigint() - startedAt) / 1e9,
        });
      });
    }

    // Correlation IDs are validated and normalized by the middleware, then
    // used consistently for both request-ID aliases and downstream context.
    const isMetricsEndpoint = req.method === "GET" && pathname === "/metrics";

    // Resolve tenant context (#800)
    const tenantId = resolveTenantId(req);
    req.tenantId = tenantId;
    res.setHeader("X-Tenant-ID", tenantId);

    // Correlation ID + trace record (#946). Every response, including the
    // metrics endpoint, carries X-Correlation-ID.
    const correlationId = correlationMiddleware(req, res, { path: pathname });
    const requestId = correlationId;

    // #1118: attach the cache manager to the request so handlers can read
    // through it without threading it through every call site.
    req.cache = cache;

    const handler = async () => {
    // Distributed Tracing with OpenTelemetry (#801)
    openTelemetryHttpMiddleware()(req, res);

    // CSP and companion security headers (#754). Set before any branch that
    // can produce a response, so an early return still carries them. The
    // nonce is stashed on the request for the one HTML page we render.
    req.cspNonce = setSecurityHeaders(req, res, config);

    // Apply response compression middleware (#721)
    if (config.compressionEnabled) {
      const compression = createCompressionMiddleware({
        threshold: config.compressionThreshold,
        gzipLevel: config.compressionGzipLevel,
        brotliLevel: config.compressionBrotliLevel,
        enableBrotli: config.compressionEnableBrotli,
        metrics,
      });
      // Apply compression to response
      await compression.middleware()(req, res);
    }

    // Access logging is attached before any routing so a request that is
    // rejected by CORS, auth, or the rate limiter is still recorded.
    if (config.accessLogEnabled && !isMetricsEndpoint) {
      const finishAccessLog = startAccessLog(req, res, {
        requestId,
        config,
        sink: accessLogSink,
      });
      res.on("finish", () => finishAccessLog({ requestBody: req.loggedBody ?? null }));
    }

    // Origin-side DDoS controls run before authentication, body parsing, or RPC work.
    // Health/observability endpoints remain available for load balancers and alerts.
    if (!isMetricsEndpoint && !["/health", "/ready", "/live"].includes(pathname)) {
      const trafficResult = await ddos.check(req);
      if (!trafficResult.allowed) return ddosResponse(res, trafficResult);
    }

    // Apply CORS headers
    if (setCorsHeaders(req, res, config)) {
      // Preflight OPTIONS request
      return res.writeHead(204).end();
    }

    // End-to-end encryption for sensitive credential data (#1049). The
    // middleware wraps sendJson/sendFormatted so any response body produced
    // downstream is encrypted with the session key the client negotiated.
    // It is a no-op unless the feature is enabled and the client presented a
    // key id, so existing clients are unaffected.
    if (isEncryptionEnabled(config)) {
      res.setHeader("X-Encryption-Supported", "aes-256-gcm");
      wrapResponseEncryption(req, res, { config, registry: encryptionKeys });
    }

    // Record analytics when response completes
    res.on("finish", () => {
      const durationMs = Math.max(0, Date.now() - startTime);
      const consumer =
        req.headers["x-api-key"] ||
        req.headers.authorization?.replace(/^Bearer\s+/i, "") ||
        "anonymous";
      const country = detectCountry(req);

      usageTracker.record(req.apiKeyId ?? consumer, {
        method: req.method,
        path: url.pathname,
        statusCode: res.statusCode,
      });

      analytics.recordRequest({
        method: req.method,
        path: url.pathname,
        statusCode: res.statusCode,
        durationMs,
        consumer,
        country,
      });
    });

        if (await handleMockApiRequest(req, res, config)) return;

    // Session key exchange (#1049). Unauthenticated by design: the key it
    // returns is only useful to the client that generated the ephemeral
    // keypair, and it carries no authority of its own. The response is
    // deliberately not encrypted — it is what establishes the key.
    if (req.method === "POST" && pathname === "/encryption/session") {
      if (validateContentType(req, res)) return;
      const body = await readJson(req, config);
      if (body.__payloadTooLarge) {
        return sendJson(res, 413, { code: "PAYLOAD_TOO_LARGE", message: "Request body exceeds the size limit." });
      }
      const validated = validateRequest(res, schemas.encryptionSession, { body });
      if (!validated.ok) return;
      try {
        const negotiated = negotiateSessionKey({
          config,
          registry: encryptionKeys,
          clientPublicKey: validated.data.body.clientPublicKey,
          clientKeyId: validated.data.body.keyId ?? null,
        });
        return sendJson(res, 201, negotiated);
      } catch (err) {
        logger.warn({ error: err.message }, "Session key negotiation failed");
        return sendJson(res, 400, {
          error: "key_exchange_failed",
          code: "KEY_EXCHANGE_FAILED",
          message: err.message,
        });
      }
    }

    // Key rotation (#1049). A client that holds a key id may ask for a fresh
    // key; the old one stays valid until its TTL elapses so in-flight
    // responses encrypted with it can still be decrypted.
    if (req.method === "POST" && pathname === "/encryption/rotate") {
      const keyId = req.headers[ENCRYPTION_KEY_ID_HEADER] ?? null;
      if (!keyId) {
        return sendJson(res, 400, {
          error: "missing_key_id",
          code: "MISSING_KEY_ID",
          message: `Provide the current session key id in the ${ENCRYPTION_KEY_ID_HEADER} header.`,
        });
      }
      const rotated = encryptionKeys.rotate(keyId);
      if (!rotated) {
        return sendJson(res, 404, {
          error: "unknown_key_id",
          code: "UNKNOWN_KEY_ID",
          message: "The supplied session key id is unknown or has expired.",
        });
      }
      res.setHeader(ENCRYPTION_KEY_ID_HEADER, rotated.keyId);
      return sendJson(res, 200, {
        keyId: rotated.keyId,
        algorithm: rotated.algorithm,
        expiresAt: rotated.expiresAt,
        previousKeyId: keyId,
      });
    }

    // Validate well-known request headers before any routing or auth work.
    if (!validateRequest(res, schemas.commonHeaders, { headers: req.headers }).ok) {
      return;
    }

    // Decrypt sensitive request fields (#1049) before any handler reads the
    // body. The body is buffered and memoised, so readJson downstream sees
    // the plaintext. A request that claims encryption but cannot be
    // decrypted is rejected rather than silently processed as plaintext.
    if (isEncryptionEnabled(config) && req.headers[ENCRYPTION_ENABLED_HEADER]) {
      const { tooLarge, buffer } = await readRawBody(req, config);
      if (tooLarge) {
        return sendJson(res, 413, {
          code: "PAYLOAD_TOO_LARGE",
          message: "Request body exceeds the size limit.",
        });
      }
      const decrypted = decryptSensitiveRequestFields({
        headers: req.headers,
        body: buffer,
        registry: encryptionKeys,
      });
      if (!decrypted.ok) {
        logger.warn({ code: decrypted.code, route: routeLabel(pathname) }, "Rejected encrypted request");
        return sendJson(res, decrypted.status, {
          error: "decryption_failed",
          code: decrypted.code,
          message: decrypted.message,
        });
      }
      if (decrypted.body !== null) {
        req.rawBody = decrypted.body;
        req.encryptionKeyId = decrypted.keyId ?? null;
      }
    }

    // Extract tier and API key ID from API key or headers early if present
    const authHeader = req.headers["authorization"] || req.headers["x-api-key"];
    if (authHeader) {
      const token = typeof authHeader === "string" ? authHeader.replace(/^Bearer\s+/i, "") : "";
      try {
        const keyRecord = await apiKeyService.validateKey(token);
        if (keyRecord) {
          req.apiKeyId = keyRecord.id;
          req.userTier = keyRecord.tier || 'free';
          req.auth = { apiKey: keyRecord };
        } else {
          const parts = token.split(":");
          if (parts.length >= 2 && ["free", "pro", "enterprise"].includes(parts[1].toLowerCase())) {
            req.userTier = parts[1].toLowerCase();
          }
        }
      } catch {
        // fallback
      }
    }
    if (req.headers["x-user-tier"]) {
      req.userTier = req.headers["x-user-tier"].toLowerCase();
    }

    // Per-endpoint deprecation warnings (#751), independent of the
    // per-version deprecation versioning.js already applied above. Runs
    // after API key extraction so usage logging/notification can be
    // attributed to the calling key.
    const deprecationRule = deprecation.match(req.method, pathname);
    if (deprecationRule) deprecation.handle(req, res, deprecationRule);

    // Rate limiting check (exempt /info, /health, /metrics)
    const isExempt = ["/info", "/health", "/ready", "/live", "/metrics"].includes(url.pathname);

    // #1052: replay prevention. Only state-changing methods are checked, and
    // operational endpoints (plus the browser-posted CSP report) are exempt
    // because they cannot carry client credentials.
    const isNonceExempt = isExempt || pathname === "/csp-report";
    const isStateChanging = !["GET", "HEAD", "OPTIONS"].includes(req.method);
    if (!isNonceExempt && isStateChanging) {
      const nonceResult = await checkNonce(req, res);
      if (!nonceResult.ok) {
        metrics?.observeNonceCollision?.(nonceResult.reason ?? "replayed");
        logger.warn(
          { code: nonceResult.code, route: routeLabel(pathname), tenantId },
          "Rejected replayed request nonce",
        );
        return sendJson(res, nonceResult.status ?? 409, {
          error: "nonce_replayed",
          code: nonceResult.code ?? "SIGNATURE_REPLAYED",
          message: nonceResult.message ?? "Request nonce has already been used.",
        });
      }
      // A fresh server nonce is attached to every accepted response so a
      // client can chain requests without reusing a nonce.
      if (nonceResult.serverNonce) {
        res.setHeader("X-Nonce", nonceResult.serverNonce);
      }
    }

    // HMAC request signing (#752). Verified before routing so no handler can
    // act on a request whose body was tampered with or replayed. Operational
    // endpoints are exempt for the same reason they skip rate limiting: a
    // probe has to work without client credentials.
    // A CSP violation report is posted by the browser itself, which has no
    // API key and no signing secret, so it can never carry a signature.
    const isSigningExempt = isExempt || pathname === "/csp-report";

    if (config.requestSigningEnabled && !isSigningExempt) {
      const mustBeSigned =
        config.requestSigningEnforce === "all" ||
        !["GET", "HEAD", "OPTIONS"].includes(req.method);

      if (mustBeSigned) {
        // Buffered here and memoised on the request; the route handler's
        // readJson call reuses these exact bytes.
        const { tooLarge, buffer } = await readRawBody(req, config);
        if (tooLarge) {
          return sendJson(res, 413, {
            code: "PAYLOAD_TOO_LARGE",
            message: "Request body exceeds the size limit.",
          });
        }

        // An explicit key id lets a caller sign with a key it is not also
        // authenticating with; otherwise the authenticated key supplies it.
        const signingKeyId = req.headers[KEY_ID_HEADER] ?? req.apiKeyId ?? null;
        const signingSecret = signingKeyId
          ? await apiKeyService.getSigningSecret(signingKeyId)
          : null;

        const verdict = verifySignedRequest({
          headers: req.headers,
          method: req.method,
          path: req.url,
          body: buffer,
          secret: signingSecret,
          nonceStore,
          maxAgeSeconds: config.requestSigningMaxAgeSeconds,
          scope: signingKeyId ?? "",
        });

        if (!verdict.ok) {
          logger.warn(
            { code: verdict.code, keyId: signingKeyId, route: routeLabel(pathname) },
            "Rejected request signature",
          );
          return sendJson(res, verdict.status, {
            error: "invalid_signature",
            code: verdict.code,
            message: verdict.message,
          });
        }
      }
    }

    if (!isExempt) {
      const rateResult = limiter.check(req, url.pathname);

      if (rateResult.whitelisted) {
        res.setHeader("X-RateLimit-Bypass", rateResult.bypass ?? "whitelist");
      } else {
        // Report whichever budget is closest to exhaustion, so a client sees
        // the limit that will actually stop it first.
        const reported = rateResult.binding ?? rateResult;
        res.setHeader("X-RateLimit-Tier", String(rateResult.tier ?? reported.rule ?? "free"));
        res.setHeader("X-RateLimit-Limit", String(reported.limit));
        res.setHeader("X-RateLimit-Remaining", String(reported.remaining));
        res.setHeader("X-RateLimit-Reset", String(reported.resetAt));
        if (!rateResult.allowed) {
          res.setHeader("X-RateLimit-Scope", rateResult.scope);
        } else if (reported.rule === "ip" || reported.rule === "user") {
          res.setHeader("X-RateLimit-Scope", reported.rule);
        } else if (rateResult.endpoint?.rule) {
          res.setHeader("X-RateLimit-Scope", "tier");
        }
      }

      if (!rateResult.allowed) {
        res.setHeader("Retry-After", String(rateResult.retryAfter));

        // An endpoint denial is not a tier problem, so it must not be dressed
        // up as one — upgrading would not raise a per-endpoint limit.
        const isEndpointDenial = rateResult.scope === "endpoint";
        // Per-IP and per-user denials are abuse controls, not tier limits.
        const isClientDenial = rateResult.scope === "ip" || rateResult.scope === "user";

        if (isClientDenial) {
          return sendJson(res, 429, {
            error: "rate_limit_exceeded",
            code: "RATE_LIMIT_EXCEEDED",
            scope: rateResult.scope,
            message: `Too many requests from this ${rateResult.scope === "ip" ? "IP address" : "account"}. Retry in ${rateResult.retryAfter}s.`,
            limit: rateResult.limit,
            retryAfter: rateResult.retryAfter,
          });
        }

        if (!isEndpointDenial && rateResult.tier === "free") {
          res.setHeader(
            "X-Upgrade-Available",
            "Upgrade to Pro or Enterprise for higher limits: https://soroban-identity.org/pricing"
          );
        }

        const windowMinutes = Math.round(
          ((rateResult.resetAt * 1000) - Date.now()) / 60000
        );

        return sendJson(res, 429, {
          error: "rate_limit_exceeded",
          code: "RATE_LIMIT_EXCEEDED",
          scope: rateResult.scope,
          message: isEndpointDenial
            ? `Rate limit exceeded for '${rateResult.rule}' (${rateResult.limit} requests per window). Retry in ${rateResult.retryAfter}s.`
            : rateResult.tier === "free"
              ? `Free tier rate limit exceeded (${rateResult.limit} req/min). Upgrade to Pro (300 req/min) or Enterprise (1200 req/min) for higher limits.`
              : `Rate limit exceeded for tier '${rateResult.tier}' (${rateResult.limit} req/min).`,
          ...(isEndpointDenial ? { rule: rateResult.rule, windowMinutes } : { tier: rateResult.tier }),
          ...(!isEndpointDenial && rateResult.tier === "free"
            ? {
                upgrade: {
                  message: "Upgrade to Pro or Enterprise for increased rate limits.",
                  upgradeUrl: "https://soroban-identity.org/pricing",
                  availableTiers: ["pro", "enterprise"],
                },
              }
            : {}),
          limit: rateResult.limit,
          retryAfter: rateResult.retryAfter,
        });
      }
    }

    // #1053: resolve the tenant before quota/limit checks so per-tenant
    // budgets apply. The tenant registry is the source of truth for limits.
    const tenant = tenantRegistry.get(tenantId) ?? null;
    req.tenant = tenant;
    if (tenant) {
      const tenantLimits = tenant.limits ?? {};
      if (
        tenantLimits.maxCredentials != null &&
        req.method === "POST" &&
        (pathname === "/credentials" || pathname === "/credentials/issue")
      ) {
        const existing = await readCredentials(config, { tenantId });
        if (existing.length >= tenantLimits.maxCredentials) {
          return sendJson(res, 429, {
            error: "tenant_limit_exceeded",
            code: "TENANT_LIMIT_EXCEEDED",
            scope: "credentials",
            tenantId,
            message: `Tenant '${tenantId}' has reached its credential limit (${tenantLimits.maxCredentials}).`,
          });
        }
      }
      if (
        tenantLimits.maxDids != null &&
        req.method === "POST" &&
        pathname === "/admin/issuers"
      ) {
        const issuers = await soroban.getIssuers();
        if (issuers.length >= tenantLimits.maxDids) {
          return sendJson(res, 429, {
            error: "tenant_limit_exceeded",
            code: "TENANT_LIMIT_EXCEEDED",
            scope: "dids",
            tenantId,
            message: `Tenant '${tenantId}' has reached its DID limit (${tenantLimits.maxDids}).`,
          });
        }
      }
    }

    // Quota check (#748): a separate budget from the rate limit above,
    // measured against calendar day/month boundaries rather than a rolling
    // window. GET /quota itself is exempt so checking your own usage never
    // consumes it.
    if (!isExempt && pathname !== "/quota") {
      const quotaResult = quota.consume(req, tenant ? { tenantId, limits: tenant.limits } : undefined);
      const binding = pickQuotaBinding(quotaResult);
      res.setHeader("X-Quota-Tier", quotaResult.tier);
      res.setHeader("X-Quota-Period", binding.period);
      res.setHeader("X-Quota-Limit", String(binding.limit));
      res.setHeader("X-Quota-Remaining", String(binding.remaining));
      res.setHeader("X-Quota-Reset", String(binding.resetAt));
      if (quotaResult.overage) res.setHeader("X-Quota-Overage", "true");

      if (!quotaResult.allowed) {
        return sendJson(res, 429, {
          error: "quota_exceeded",
          code: "QUOTA_EXCEEDED",
          scope: quotaResult.scope,
          tier: quotaResult.tier,
          message: `${quotaResult.scope === "daily" ? "Daily" : "Monthly"} API quota exceeded for tier '${quotaResult.tier}'.`,
          daily: quotaResult.daily,
          monthly: quotaResult.monthly,
        });
      }
    }

    // #1119: API usage metering. Runs after auth/quota so the call is
    // attributed to the right key and tier, and after the quota check so a
    // rejected request is not billed. Operational endpoints are exempt.
    if (!isExempt && pathname !== "/quota") {
      const meterResult = await meter(req, res, { pathname, tenantId });
      if (meterResult && meterResult.blocked) {
        return sendJson(res, 429, {
          error: "usage_quota_exceeded",
          code: "USAGE_QUOTA_EXCEEDED",
          tier: meterResult.tier,
          message: meterResult.message ?? "API usage quota exceeded for this billing period.",
          usage: meterResult.usage,
          limit: meterResult.limit,
        });
      }
      if (meterResult?.headers) {
        for (const [name, value] of Object.entries(meterResult.headers)) {
          res.setHeader(name, value);
        }
      }
    }

        if (req.method === "GET" && pathname === "/info") {
          return sendJson(res, 200, {
            version: SERVER_VERSION,
            apiVersion: version,
            supportedVersions: SUPPORTED_VERSIONS,
            features: SERVER_FEATURES,
            minSdkVersion: MIN_SDK_VERSION,
            encryption: {
              enabled: isEncryptionEnabled(config),
              algorithm: "aes-256-gcm",
              keyExchange: "/encryption/session",
              rotation: "/encryption/rotate",
              keyIdHeader: ENCRYPTION_KEY_ID_HEADER,
              encryptedFields: ["claims", "subject", "credentialSubject"],
            },
          });
        }

        // CSP violation reports (#754). Unauthenticated by necessity — the
        // browser posts these on its own behalf, with no credentials — so the
        // handler only ever logs and counts, and never trusts the contents.
        if (req.method === "POST" && pathname === "/csp-report") {
          const { tooLarge, buffer } = await readRawBody(req, config);
          if (tooLarge) {
            return sendJson(res, 413, {
              code: "PAYLOAD_TOO_LARGE",
              message: "Request body exceeds the size limit.",
            });
          }

          let reports = [];
          try {
            reports = normalizeCspReports(JSON.parse(buffer.toString("utf8") || "{}"));
          } catch {
            // A malformed report is the browser's problem, not something to
            // surface as a server error; it is counted as unparseable and
            // dropped.
            logger.warn({ route: "/csp-report" }, "Discarded unparseable CSP report");
            return res.writeHead(204).end();
          }

          for (const report of reports) {
            logger.warn(
              {
                directive: report.directive,
                blockedUri: report.blockedUri,
                documentUri: report.documentUri,
                sourceFile: report.sourceFile,
                lineNumber: report.lineNumber,
                enforced: !config.cspReportOnly,
              },
              "CSP violation reported",
            );
            metrics?.observeCspViolation?.(report.directive);
          }

          // 204: the browser discards the response body, and there is nothing
          // useful to tell it.
          return res.writeHead(204).end();