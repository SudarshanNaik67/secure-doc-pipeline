import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createApp, MockBoxClient, BoxApiError, type BoxUploader } from '../src/index';

const KEY = 'test-key';
const SCAN_ID = '123e4567-e89b-12d3-a456-426614174000';

// Fake Box client: no network, no credentials needed.
const fakeBox: BoxUploader = {
  async upload(input) {
    return { id: '123', name: input.fileName, size: input.data.length, parentFolderId: '0' };
  },
};

async function withServer(box: BoxUploader, run: (baseUrl: string) => Promise<void>): Promise<void> {
  const app = createApp({ port: 0, internalApiKey: KEY, maxFileBytes: 1024 }, box);
  const server = app.listen(0);
  try {
    const { port } = server.address() as AddressInfo;
    await run(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

function uploadForm(content = 'hello', scanId: string | null = SCAN_ID): FormData {
  const form = new FormData();
  if (scanId) form.append('scan_id', scanId);
  form.append('file', new Blob([content]), 'a.txt');
  return form;
}

test('GET /health returns ok', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/health`);
    assert.equal(res.status, 200);
  });
});

test('POST /upload without key is rejected', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/upload`, { method: 'POST' });
    assert.equal(res.status, 401);
  });
});

test('POST /upload without file returns 400', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/upload`, { method: 'POST', headers: { 'x-internal-api-key': KEY } });
    assert.equal(res.status, 400);
  });
});

test('POST /upload with non-UUID scan_id returns 400', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/upload`, {
      method: 'POST',
      headers: { 'x-internal-api-key': KEY },
      body: uploadForm('hello', 'not-a-uuid'),
    });
    assert.equal(res.status, 400);
  });
});

test('POST /upload with valid key and file returns 201', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/upload`, {
      method: 'POST',
      headers: { 'x-internal-api-key': KEY },
      body: uploadForm(),
    });
    assert.equal(res.status, 201);
    const body = (await res.json()) as { box_file_id: string; name: string };
    assert.equal(body.box_file_id, '123');
    assert.equal(body.name, '123e4567_a.txt');
  });
});

test('oversized file returns 413', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/upload`, {
      method: 'POST',
      headers: { 'x-internal-api-key': KEY },
      body: uploadForm('x'.repeat(2048)),
    });
    assert.equal(res.status, 413);
  });
});

test('Box API failure is mapped to 502', async () => {
  const failingBox: BoxUploader = {
    async upload() {
      throw new BoxApiError(401, 'unauthorized', 'bad token');
    },
  };
  await withServer(failingBox, async (base) => {
    const res = await fetch(`${base}/upload`, {
      method: 'POST',
      headers: { 'x-internal-api-key': KEY },
      body: uploadForm(),
    });
    assert.equal(res.status, 502);
    const body = (await res.json()) as { error: string };
    assert.equal(body.error, 'box_upstream_error');
  });
});

test('mock mode stores the file and exposes it for read-back (auth required)', async () => {
  await withServer(new MockBoxClient(), async (base) => {
    const up = await fetch(`${base}/upload`, {
      method: 'POST',
      headers: { 'x-internal-api-key': KEY },
      body: uploadForm('masked content'),
    });
    assert.equal(up.status, 201);
    const { box_file_id } = (await up.json()) as { box_file_id: string };

    const denied = await fetch(`${base}/mock/files/${box_file_id}`);
    assert.equal(denied.status, 401);

    const ok = await fetch(`${base}/mock/files/${box_file_id}`, { headers: { 'x-internal-api-key': KEY } });
    assert.equal(ok.status, 200);
    assert.equal(await ok.text(), 'masked content');
  });
});

test('mock read-back route does not exist outside mock mode', async () => {
  await withServer(fakeBox, async (base) => {
    const res = await fetch(`${base}/mock/files/1000`, { headers: { 'x-internal-api-key': KEY } });
    assert.equal(res.status, 404);
  });
});
