import express from 'express';

const app = express();
const cache = new Map<string, unknown>();
cache.get('/not-a-route');

const client = { get: (url: string, cb: () => void) => cb() };
client.get('/not-a-route-either', () => 1);

app.get('trust proxy');
