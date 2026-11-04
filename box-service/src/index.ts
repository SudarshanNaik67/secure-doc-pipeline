/**
 * Box Cloud Integration Service (Microservice 2)
 * ----------------------------------------------
 * Accepts sanitized files from the DLP scanner and uploads them to Box using
 * the Box REST API (https://developer.box.com/reference/post-files-content/).
 *
 * Modes (choose via environment variables):
 *   0. BOX_MOCK_MODE=true   - NO Box account needed. Files are kept in memory and
 *                             can be read back via GET /mock/files/:id. Ideal for
 *                             demos, local development and CI.
 *   1. BOX_DEVELOPER_TOKEN  - easiest for a real Box sandbox (token expires in 60 min)
 *   2. Client Credentials Grant (CCG): BOX_CLIENT_ID + BOX_CLIENT_SECRET + BOX_ENTERPRISE_ID
 *
 * The Box integration sits behind the `BoxUploader` interface, so the REST
 * implementation below can be replaced by the official SDK without touching
 * the HTTP layer, and the HTTP layer can be tested with a fake.
 */
import crypto from 'node:crypto';
import express, {
  type NextFunction as Next,
  type Request as Req,
  type Response as Res,
} from 'express';
import helmet from 'helmet';
import multer from 'multer';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
export interface AppConfig {
  port: number;
  internalApiKey: string;
  maxFileBytes: number;
}

export interface UploadInput {
  fileName: string;
  contentType: string;
  data: Buffer;
}

export interface UploadResult {
  id: string;
  name: string;
  size: number;
  parentFolderId: string;
}

export interface BoxUploader {
  upload(input: UploadInput): Promise<UploadResult>;
}

export interface BoxClientConfig {
  developerToken?: string;
  clientId?: string;
  clientSecret?: string;
  enterpriseId?: string;
  parentFolderId: string; // "0" is the root folder of the account
}

/** Error carrying Box's own error code so callers can log/map it. */
export class BoxApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly requestId?: string,
  ) {
    super(message);
    this.name = 'BoxApiError';
  }
}

// ---------------------------------------------------------------------------
// Structured logging (one JSON object per line: easy to ship to any log stack)
// ---------------------------------------------------------------------------
function log(level: 'info' | 'warn' | 'error', msg: string, extra: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...extra }));
}

// ---------------------------------------------------------------------------
// Box REST client wrapper
// ---------------------------------------------------------------------------
const BOX_TOKEN_URL = 'https://api.box.com/oauth2/token';
const BOX_UPLOAD_URL = 'https://upload.box.com/api/2.0/files/content';

export class BoxRestClient implements BoxUploader {
  private cachedToken?: { value: string; expiresAt: number };

  constructor(private readonly cfg: BoxClientConfig) {}

  /** Build a client from environment variables, validating that auth is configured. */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): BoxRestClient {
    const cfg: BoxClientConfig = {
      developerToken: env.BOX_DEVELOPER_TOKEN || undefined,
      clientId: env.BOX_CLIENT_ID || undefined,
      clientSecret: env.BOX_CLIENT_SECRET || undefined,
      enterpriseId: env.BOX_ENTERPRISE_ID || undefined,
      parentFolderId: env.BOX_PARENT_FOLDER_ID || '0',
    };
    const hasCcg = Boolean(cfg.clientId && cfg.clientSecret && cfg.enterpriseId);
    if (!cfg.developerToken && !hasCcg) {
      throw new Error(
        'Box auth not configured: set BOX_MOCK_MODE=true, or BOX_DEVELOPER_TOKEN, ' +
          'or BOX_CLIENT_ID + BOX_CLIENT_SECRET + BOX_ENTERPRISE_ID',
      );
    }
    return new BoxRestClient(cfg);
  }

  /** Returns a bearer token, using the CCG flow with in-memory caching when needed. */
  private async getAccessToken(): Promise<string> {
    if (this.cfg.developerToken) return this.cfg.developerToken;

    const now = Date.now();
    if (this.cachedToken && this.cachedToken.expiresAt - 60_000 > now) {
      return this.cachedToken.value; // still valid (60s safety margin)
    }

    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.cfg.clientId as string,
      client_secret: this.cfg.clientSecret as string,
      box_subject_type: 'enterprise',
      box_subject_id: this.cfg.enterpriseId as string,
    });
    const res = await fetch(BOX_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw await this.toApiError(res, 'Failed to obtain Box access token');

    const json = (await res.json()) as { access_token: string; expires_in: number };
    this.cachedToken = {
      value: json.access_token,
      expiresAt: now + json.expires_in * 1000,
    };
    return json.access_token;
  }

  /** Upload a file (< 50 MB, per Box's simple upload API) into the configured folder. */
  async upload(input: UploadInput): Promise<UploadResult> {
    const token = await this.getAccessToken();

    // Box requires the `attributes` part to come BEFORE the `file` part.
    const form = new FormData();
    form.append(
      'attributes',
      JSON.stringify({ name: input.fileName, parent: { id: this.cfg.parentFolderId } }),
    );
    form.append(
      'file',
      new Blob([new Uint8Array(input.data)], { type: input.contentType }),
      input.fileName,
    );

    const res = await fetch(BOX_UPLOAD_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: form,
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw await this.toApiError(res, 'Box upload failed');

    const json = (await res.json()) as {
      entries?: Array<{ id: string; name: string; size: number }>;
    };
    const entry = json.entries?.[0];
    if (!entry) throw new BoxApiError(502, 'invalid_response', 'Box returned no file entry');

    return {
      id: entry.id,
      name: entry.name,
      size: entry.size,
      parentFolderId: this.cfg.parentFolderId,
    };
  }

  /** Convert a failed Box HTTP response into a typed error. */
  private async toApiError(res: globalThis.Response, fallback: string): Promise<BoxApiError> {
    let body: { code?: string; message?: string; request_id?: string } = {};
    try {
      body = (await res.json()) as typeof body;
    } catch {
      /* non-JSON error body: fall through to defaults */
    }
    return new BoxApiError(
      res.status,
      body.code ?? 'unknown',
      body.message ?? fallback,
      body.request_id,
    );
  }
}

// ---------------------------------------------------------------------------
// Mock Box client (BOX_MOCK_MODE=true): in-memory, no network, no credentials
// ---------------------------------------------------------------------------
interface MockFile {
  name: string;
  contentType: string;
  data: Buffer;
}

export class MockBoxClient implements BoxUploader {
  private readonly files = new Map<string, MockFile>();
  private nextId = 1000;

  constructor(private readonly maxFiles = 100) {}

  async upload(input: UploadInput): Promise<UploadResult> {
    const id = String(this.nextId++);
    this.files.set(id, { name: input.fileName, contentType: input.contentType, data: input.data });
    // Bound memory use: evict the oldest entry once the cap is exceeded.
    if (this.files.size > this.maxFiles) {
      const oldest = this.files.keys().next().value;
      if (oldest !== undefined) this.files.delete(oldest);
    }
    return { id, name: input.fileName, size: input.data.length, parentFolderId: '0' };
  }

  get(id: string): MockFile | undefined {
    return this.files.get(id);
  }
}

// ---------------------------------------------------------------------------
// HTTP layer helpers
// ---------------------------------------------------------------------------
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sanitizeFileName(name: string): string {
  const base = name.replace(/\\/g, '/').split('/').pop() ?? '';
  return base.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '').slice(0, 128) || 'unnamed';
}

/** Constant-time string comparison (hashing equalises lengths first). */
function safeEqual(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Service-to-service auth: only callers presenting the shared key may use the API. */
function requireInternalKey(expected: string) {
  return (req: Req, res: Res, next: Next): void => {
    const provided = req.header('x-internal-api-key') ?? '';
    if (!provided || !safeEqual(provided, expected)) {
      res.status(401).json({ error: 'unauthorized', message: 'Invalid or missing internal API key' });
      return;
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Express app factory (exported so tests can inject a fake Box client)
// ---------------------------------------------------------------------------
export function createApp(config: AppConfig, box: BoxUploader): express.Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());

  // Memory storage: files are small, text-only and size-capped.
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: config.maxFileBytes, files: 1, fields: 5 },
  });

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  app.post(
    '/upload',
    requireInternalKey(config.internalApiKey), // authenticate BEFORE parsing the body
    upload.single('file'),
    async (req: Req, res: Res, next: Next): Promise<void> => {
      try {
        if (!req.file) {
          res.status(400).json({ error: 'missing_file', message: 'Multipart field "file" is required' });
          return;
        }
        const scanId = typeof req.body?.scan_id === 'string' ? req.body.scan_id : '';
        if (!UUID_RE.test(scanId)) {
          res.status(400).json({ error: 'invalid_scan_id', message: 'Field "scan_id" must be a UUID' });
          return;
        }

        // Prefix with the scan id: traceable back to the audit record and avoids
        // Box's 409 "item_name_in_use" conflicts for repeated file names.
        const boxName = `${scanId.slice(0, 8)}_${sanitizeFileName(req.file.originalname)}`;

        const result = await box.upload({
          fileName: boxName,
          contentType: req.file.mimetype || 'application/octet-stream',
          data: req.file.buffer,
        });

        log('info', 'file_uploaded_to_box', {
          scan_id: scanId,
          box_file_id: result.id,
          size: result.size,
          dlp_findings: req.body?.dlp_findings,
          mock: box instanceof MockBoxClient,
        });
        res.status(201).json({
          box_file_id: result.id,
          name: result.name,
          size: result.size,
          parent_folder_id: result.parentFolderId,
          scan_id: scanId,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  // Mock mode only: read back what "Box" received so a demo can prove masking.
  if (box instanceof MockBoxClient) {
    app.get('/mock/files/:id', requireInternalKey(config.internalApiKey), (req: Req, res: Res) => {
      const file = box.get(String(req.params.id));
      if (!file) {
        res.status(404).json({ error: 'not_found' });
        return;
      }
      res.type('text/plain').send(file.data.toString('utf-8'));
    });
  }

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  // Central error handler (Express recognises it by the 4-argument signature).
  app.use((err: unknown, _req: Req, res: Res, _next: Next) => {
    if (err instanceof multer.MulterError) {
      res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code, message: err.message });
      return;
    }
    if (err instanceof BoxApiError) {
      log('error', 'box_api_error', { status: err.status, code: err.code, request_id: err.requestId });
      res.status(502).json({ error: 'box_upstream_error', box_code: err.code, message: err.message });
      return;
    }
    log('error', 'unhandled_error', { message: err instanceof Error ? err.message : String(err) });
    res.status(500).json({ error: 'internal_error' });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Process entrypoint
// ---------------------------------------------------------------------------
function main(): void {
  const internalApiKey = process.env.INTERNAL_API_KEY;
  if (!internalApiKey) {
    console.error('FATAL: INTERNAL_API_KEY is required');
    process.exit(1);
  }

  const config: AppConfig = {
    port: Number(process.env.PORT ?? 3000),
    internalApiKey,
    maxFileBytes: Number(process.env.MAX_FILE_BYTES ?? 5 * 1024 * 1024),
  };

  const mockMode = (process.env.BOX_MOCK_MODE ?? 'false').toLowerCase() === 'true';
  let box: BoxUploader;
  try {
    box = mockMode ? new MockBoxClient() : BoxRestClient.fromEnv();
  } catch (err) {
    console.error(`FATAL: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
  if (mockMode) log('warn', 'box_mock_mode_enabled', { note: 'files are NOT sent to Box' });

  const app = createApp(config, box);
  const server = app.listen(config.port, () => log('info', 'box_service_listening', { port: config.port }));

  // Graceful shutdown so in-flight uploads finish during rolling updates.
  const shutdown = (signal: string): void => {
    log('info', 'shutting_down', { signal });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (require.main === module) {
  main();
}
