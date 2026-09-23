export default async function orphanPlugin(fastify) {
  fastify.get('/orphan', async () => 'never registered');
}
