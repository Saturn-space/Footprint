import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { apiRouter } from './src/server/routes/api';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProd = process.env.NODE_ENV === 'production';

  // Body parsing with 10MB limit for secure XML/JSON reconnaissance dumps
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Mount versioned REST API
  app.use('/api/v1', apiRouter);

  // Vite development middleware or static production serving
  if (!isProd) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true, port: PORT, host: '0.0.0.0' },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[FootprintIQ Server] Server running on http://0.0.0.0:${PORT}`);
    console.log(`[FootprintIQ Server] API v1 available at http://0.0.0.0:${PORT}/api/v1`);
  });
}

startServer().catch(err => {
  console.error('[FootprintIQ Server] Startup Error:', err);
  process.exit(1);
});
