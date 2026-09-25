import http from 'node:http';
import { URL } from 'node:url';
const secure = process.env.CODESENTINEL_SECURE === '1';
const state = { transfers: 0, webhookProcessed: 0, role: 'user', files: [] };
const json = (res, value) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
const send = (res, status, text, headers = {}) => { res.writeHead(status, { 'content-type': 'text/plain', ...headers }); res.end(text); };
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1'); let body = '';
  for await (const chunk of req) { body += chunk; if (body.length > 32_000) break; }
  if (req.method === 'GET' && url.pathname === '/transfer-state') return json(res, { transfers: state.transfers });
  if (req.method === 'GET' && url.pathname === '/webhook-state') return json(res, { processed: state.webhookProcessed });
  if (req.method === 'GET' && url.pathname === '/profile-state') return json(res, { role: state.role, displayName: 'CodeSentinel' });
  if (req.method === 'GET' && url.pathname === '/upload-state') return json(res, { files: state.files.slice(0, 4).map((file) => ({ filename: file.filename, type: file.type })) });
  if (url.pathname === '/transfer' && req.method === 'POST') { if (secure && req.headers.origin === 'https://cross-site.invalid') return send(res, 403, 'csrf control rejected request'); state.transfers += 1; return send(res, 200, 'transfer accepted'); }
  if (url.pathname === '/webhook' && req.method === 'POST') { if (secure && req.headers['x-codesentinel-signature'] !== 'valid-codesentinel-signature') return send(res, 401, 'signature rejected'); state.webhookProcessed += 1; return send(res, 202, 'event processed'); }
  if (url.pathname === '/profile' && req.method === 'POST') { const params = new URLSearchParams(body); if (!secure && params.get('role')) state.role = params.get('role'); return send(res, 200, 'profile updated'); }
  if (url.pathname === '/upload' && req.method === 'POST') { const filename = /filename="([^"]+)"/.exec(body)?.[1] ?? ''; const type = /Content-Type:\s*([^\r\n]+)/i.exec(body)?.[1] ?? 'application/octet-stream'; if (secure && filename.toLowerCase().endsWith('.html')) return send(res, 415, 'file type rejected'); state.files.push({ filename, type }); return send(res, 201, 'file stored'); }
  if (url.pathname === '/jwt' && req.method === 'GET') { const invalidSignature = url.searchParams.get('token')?.endsWith('.invalid-signature'); return send(res, secure && invalidSignature ? 401 : 200, secure ? 'authorization rejected' : 'protected authorization granted'); }
  if (url.pathname === '/session-cookie') return send(res, 200, 'ok', { 'set-cookie': secure ? 'session=fixture-secret; Secure; HttpOnly; SameSite=Lax' : 'session=fixture-secret' });
  if (url.pathname === '/cors') return send(res, 200, 'ok', secure ? { 'access-control-allow-origin': 'https://app.example' } : { 'access-control-allow-origin': '*' });
  send(res, 404, 'not found');
});
server.listen(Number(process.env.PORT), '127.0.0.1');
