/**
 * VulnAPI - Express.js Implementation
 *
 * Deliberately vulnerable API for security learning.
 * WARNING: This API contains intentional security vulnerabilities.
 * Do NOT deploy in production.
 */

import express from 'express';
import cors from 'cors';
import { graphqlHTTP } from 'express-graphql';

import { initDatabase, seedDatabase } from './database.js';
import { decodeToken } from './middleware/auth.js';
import { db } from './database.js';

// Routes
import authRouter from './routes/auth.js';
import { usersRouter, usersRouterV1 } from './routes/users.js';
import productsRouter from './routes/products.js';
import toolsRouter from './routes/tools.js';
import flagsRouter from './routes/flags.js';
import docsRouter from './routes/docs.js';
import graphqlSchema from './graphql/schema.js';

/**
 * Check if running in a production-like environment and warn/block.
 * This application is INTENTIONALLY VULNERABLE and should NEVER
 * be deployed in production environments.
 */
function checkProductionEnvironment() {
  const indicators = {
    'PRODUCTION': process.env.PRODUCTION,
    'PROD': process.env.PROD,
    'NODE_ENV=production': process.env.NODE_ENV === 'production' ? 'true' : null,
    'ENVIRONMENT=production': process.env.ENVIRONMENT === 'production' ? 'true' : null,
    'AWS_EXECUTION_ENV': process.env.AWS_EXECUTION_ENV,
    'AWS_LAMBDA_FUNCTION_NAME': process.env.AWS_LAMBDA_FUNCTION_NAME,
    'KUBERNETES_SERVICE_HOST': process.env.KUBERNETES_SERVICE_HOST,
    'ECS_CONTAINER_METADATA_URI': process.env.ECS_CONTAINER_METADATA_URI,
    'GOOGLE_CLOUD_PROJECT': process.env.GOOGLE_CLOUD_PROJECT,
    'HEROKU_APP_NAME': process.env.HEROKU_APP_NAME,
    'VERCEL': process.env.VERCEL,
    'RENDER': process.env.RENDER,
  };

  const detected = Object.entries(indicators).filter(([_, v]) => v);

  if (detected.length > 0) {
    console.error(`
================================================================================
                    CRITICAL SECURITY WARNING
================================================================================

  API Security Dojo has detected a PRODUCTION-LIKE environment!

  Detected indicators:`);
    detected.forEach(([k, v]) => console.error(`    - ${k}: ${v}`));
    console.error(`
  THIS APPLICATION IS INTENTIONALLY VULNERABLE!
  It contains security vulnerabilities by design for educational purposes.

  DO NOT DEPLOY IN PRODUCTION - You WILL be compromised!

================================================================================
`);

    if (process.env.DOJO_FORCE_START !== 'true') {
      console.error('  To override this safety check (NOT RECOMMENDED), set:');
      console.error('    DOJO_FORCE_START=true\n');
      process.exit(1);
    } else {
      console.error('  WARNING: DOJO_FORCE_START=true detected.');
      console.error('  Proceeding despite production environment detection.');
      console.error('  YOU HAVE BEEN WARNED!\n');
    }
  }
}

// Check production environment before proceeding
checkProductionEnvironment();

const app = express();
const PORT = process.env.PORT || 3001;
const MODE = process.env.DOJO_MODE || 'challenge';

// ==================== Middleware ====================

// Parse JSON bodies
app.use(express.json());

// VULNERABILITY V08: CORS misconfiguration - allows all origins
app.use(cors({
  origin: '*',  // VULNERABLE: Should be specific origins
  credentials: true,
  methods: ['*'],
  allowedHeaders: ['*'],
  exposedHeaders: ['*'],
}));

// ==================== Routes ====================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'VulnAPI',
    version: '0.2.0',
    mode: MODE,
    implementation: 'Express.js',
    message: 'Welcome to VulnAPI - A deliberately vulnerable API',
    endpoints: {
      auth: '/api/login, /api/register',
      users: '/api/users',
      products: '/api/products',
      tools: '/api/tools',
      graphql: '/graphql/',
      swagger_docs: '/docs (not implemented)',
    },
    mode_info: {
      current: MODE,
      challenge: 'Limited info - find vulnerabilities yourself',
      documentation: 'Full details - exploitation steps and remediation',
      switch: 'Set DOJO_MODE=documentation to enable full docs',
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    implementation: 'express',
    debug: process.env.DEBUG === 'true'
  });
});

// API routes
app.use('/api', authRouter);
app.use('/api', usersRouter);
app.use('/api', productsRouter);
app.use('/api', toolsRouter);
app.use('/api', flagsRouter);

// VULNERABILITY V09: Old API version still accessible
app.use('/api/v1', usersRouterV1);

// GraphQL endpoint
// VULNERABILITIES:
// - G01: Introspection enabled (graphiql: true)
// - G02: No query depth limits
// - G03: Batching allowed (default behavior)
// - G04: Field suggestions in errors (default behavior)
// - G05: Missing authorization on resolvers
app.use('/graphql', graphqlHTTP((req) => {
  // Extract user from token for context (optional auth)
  let user = null;
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const payload = decodeToken(token);

    if (payload) {
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.user_id);
    }
  }

  return {
    schema: graphqlSchema,
    graphiql: true,  // VULNERABILITY G01: GraphiQL exposed
    context: { user },
    customFormatErrorFn: (error) => {
      // VULNERABILITY G04: Field suggestions in error messages
      return {
        message: error.message,
        locations: error.locations,
        path: error.path,
        // Include stack trace in development
        stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
      };
    }
  };
}));

// Documentation endpoints
app.use('/api/docs', docsRouter);

// ==================== Start Server ====================

// Initialize database
initDatabase();
seedDatabase();

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   VulnAPI - Express.js Implementation                     ║
║   ⚠️  WARNING: Intentionally Vulnerable API               ║
║                                                           ║
║   Mode: ${MODE.padEnd(49)}║
║   Server running on http://localhost:${PORT}               ║
║                                                           ║
║   Endpoints:                                              ║
║   - REST API: http://localhost:${PORT}/api                 ║
║   - GraphQL:  http://localhost:${PORT}/graphql/            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});
