import Fastify from 'fastify';

const app = Fastify();
const cache = new Map<string, unknown>();
cache.get('/not-a-route');

function lookup(cache: Map<string, string>) {
  return cache.get('/also-not-a-route', 'fallback');
}

const client = { get: (url: string, cb: () => void) => cb() };
client.get('/not-a-route-either', () => 1);

app.get('trust-proxy-setting');
