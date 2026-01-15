/**
 * Documentation router for vulnerability explanations.
 *
 * This module provides endpoints to access detailed documentation
 * about each vulnerability when the API is in documentation mode.
 */

import { Router } from 'express';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const router = Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load vulnerabilities documentation
const DOCS_PATH = join(__dirname, '..', 'docs', 'vulnerabilities.json');
const MODE = process.env.DOJO_MODE || 'challenge';

function loadVulnerabilities() {
  try {
    const data = readFileSync(DOCS_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    return { version: '1.0.0', vulnerabilities: [] };
  }
}

function checkDocumentationMode(req, res, next) {
  if (MODE !== 'documentation') {
    return res.status(403).json({
      error: 'Documentation mode is disabled',
      message: 'Set DOJO_MODE=documentation to access vulnerability details',
      current_mode: MODE,
    });
  }
  next();
}

/**
 * GET /api/docs/mode
 * Get the current API mode
 */
router.get('/mode', (req, res) => {
  res.json({
    mode: MODE,
    documentation_enabled: MODE === 'documentation',
    description: MODE === 'challenge'
      ? 'Challenge mode: Limited information, find vulnerabilities yourself'
      : 'Documentation mode: Full exploitation details and remediation',
  });
});

/**
 * GET /api/docs/stats
 * Get statistics about documented vulnerabilities
 */
router.get('/stats', (req, res) => {
  const data = loadVulnerabilities();
  const vulnerabilities = data.vulnerabilities || [];

  const stats = {
    total: vulnerabilities.length,
    by_severity: {},
    by_category: {},
    rest_api: 0,
    graphql: 0,
  };

  for (const vuln of vulnerabilities) {
    // Count by severity
    const severity = vuln.severity;
    stats.by_severity[severity] = (stats.by_severity[severity] || 0) + 1;

    // Count by category
    const category = vuln.category;
    stats.by_category[category] = (stats.by_category[category] || 0) + 1;

    // Count REST vs GraphQL
    if (vuln.id.startsWith('V')) {
      stats.rest_api++;
    } else if (vuln.id.startsWith('G')) {
      stats.graphql++;
    }
  }

  res.json(stats);
});

/**
 * GET /api/docs/categories
 * List all vulnerability categories
 */
router.get('/categories', (req, res) => {
  const data = loadVulnerabilities();
  const vulnerabilities = data.vulnerabilities || [];

  const categories = {};
  for (const vuln of vulnerabilities) {
    const cat = vuln.category;
    if (!categories[cat]) {
      categories[cat] = { name: cat, count: 0, vulnerabilities: [] };
    }
    categories[cat].count++;
    categories[cat].vulnerabilities.push(vuln.id);
  }

  res.json(Object.values(categories));
});

/**
 * GET /api/docs/vulnerabilities
 * List all documented vulnerabilities
 *
 * In challenge mode: Returns basic information only (id, name, category)
 * In documentation mode: Returns full details including exploitation steps
 */
router.get('/vulnerabilities', (req, res) => {
  const { category, severity } = req.query;
  const data = loadVulnerabilities();
  let vulnerabilities = data.vulnerabilities || [];

  // Filter by category if specified
  if (category) {
    vulnerabilities = vulnerabilities.filter(v => v.category === category);
  }

  // Filter by severity if specified
  if (severity) {
    vulnerabilities = vulnerabilities.filter(v => v.severity === severity);
  }

  // Return limited info in both modes for the list
  const result = vulnerabilities.map(v => ({
    id: v.id,
    name: v.name,
    category: v.category,
    severity: v.severity,
    owasp: v.owasp,
    cwe: v.cwe,
    description: v.description,
  }));

  res.json(result);
});

/**
 * GET /api/docs/vulnerabilities/:id
 * Get detailed documentation for a specific vulnerability
 *
 * Requires documentation mode to be enabled.
 */
router.get('/vulnerabilities/:id', checkDocumentationMode, (req, res) => {
  const { id } = req.params;
  const data = loadVulnerabilities();
  const vulnerabilities = data.vulnerabilities || [];

  const vuln = vulnerabilities.find(v => v.id === id);

  if (!vuln) {
    return res.status(404).json({ detail: `Vulnerability ${id} not found` });
  }

  res.json(vuln);
});

// Key differences for each vulnerability (educational summaries)
const KEY_DIFFERENCES = {
  V01: 'Add authorization check: verify user owns the resource or has admin role',
  V02: 'Use strong secrets from environment + generic error messages',
  V03: 'Use response models (DTOs) to filter sensitive fields',
  V04: 'Implement rate limiting with sliding window or token bucket',
  V05: 'Whitelist allowed fields, never bind request directly to model',
  V06: 'Use parameterized queries, never concatenate user input into SQL',
  V07: 'Validate input strictly, use safe APIs instead of shell execution',
  V08: 'Configure CORS properly, disable debug endpoints in production',
  V09: 'Deprecate and remove old API versions, apply same security controls',
  V10: 'Log security events, implement alerting on suspicious patterns',
  G01: 'Disable introspection in production',
  G02: 'Set query depth limit: max_depth=10',
  G03: 'Limit batch size and implement query cost analysis',
  G04: 'Disable field suggestions in production errors',
  G05: 'Add authorization checks to all resolvers',
};

/**
 * GET /api/docs/compare
 * List all available code comparisons
 */
router.get('/compare', (req, res) => {
  const data = loadVulnerabilities();
  const vulnerabilities = data.vulnerabilities || [];

  const result = vulnerabilities.map(v => ({
    id: v.id,
    name: v.name,
    key_difference: KEY_DIFFERENCES[v.id] || '',
  }));

  res.json(result);
});

/**
 * GET /api/docs/compare/:id
 * Compare vulnerable vs secure code
 * Available in BOTH challenge and documentation modes
 */
router.get('/compare/:id', (req, res) => {
  const { id } = req.params;
  const data = loadVulnerabilities();
  const vulnerabilities = data.vulnerabilities || [];

  const vuln = vulnerabilities.find(v => v.id === id);

  if (!vuln) {
    return res.status(404).json({ detail: `Vulnerability ${id} not found` });
  }

  res.json({
    id: vuln.id,
    name: vuln.name,
    vulnerable_code: vuln.vulnerable_code,
    secure_code: vuln.secure_code,
    key_difference: KEY_DIFFERENCES[id] || 'See secure_code for the fix',
    remediation: vuln.remediation,
    owasp: vuln.owasp,
    cwe: vuln.cwe,
  });
});

export default router;
