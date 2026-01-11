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
const MODE = process.env.VULNAPI_MODE || 'challenge';

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
      message: 'Set VULNAPI_MODE=documentation to access vulnerability details',
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

export default router;
