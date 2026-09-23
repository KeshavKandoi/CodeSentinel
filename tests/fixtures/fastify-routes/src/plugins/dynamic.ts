export default async function dynamicPlugin(fastify) {
  fastify.get('/static-in-dynamic', async () => ({}));
  fastify.get(buildPath('reports'), async () => []);
}
