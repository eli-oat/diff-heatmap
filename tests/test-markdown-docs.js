#!/usr/bin/env node

/**
 * Test: Markdown and Documentation File Handling
 * 
 * Verifies that markdown/text files don't get over-scored with
 * code-specific patterns while still catching real security issues.
 */

const { scoreWithRules, detectLanguage } = require('../diff-heatmap.js');

console.log('Testing Markdown/Documentation Handling\n');

// Test language detection
console.log('Language Detection:');
console.log('  README.md ->', detectLanguage('README.md'));
console.log('  test.txt ->', detectLanguage('test.txt'));
console.log('  app.js ->', detectLanguage('app.js'));
console.log();

const tests = [
  {
    name: 'SQL in markdown documentation',
    code: 'Use parameterized queries: SELECT * FROM users WHERE id = ?',
    language: 'markdown',
    expectLow: true,
    note: 'SQL examples in docs should not be flagged'
  },
  {
    name: 'Actual SQL injection in JS',
    code: 'const query = `SELECT * FROM users WHERE id = ${userId}`',
    language: 'javascript',
    expectHigh: true,
    note: 'Actual code should be flagged'
  },
  {
    name: 'Loose equality example in markdown',
    code: 'Avoid using == in JavaScript, use === instead',
    language: 'markdown',
    expectLow: true,
    note: 'Discussing == in docs should not be flagged'
  },
  {
    name: 'Actual loose equality in JS',
    code: 'if (user == admin) return true',
    language: 'javascript',
    expectHigh: true,
    note: 'Actual code should be flagged'
  },
  {
    name: 'API key in markdown',
    code: 'Set your API key: API_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz"',
    language: 'markdown',
    expectHigh: true,
    note: 'Secrets should be flagged even in docs'
  },
  {
    name: 'API key in code',
    code: 'const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"',
    language: 'javascript',
    expectHigh: true,
    note: 'Secrets should always be flagged'
  },
  {
    name: 'DELETE keyword in plain text',
    code: 'Click the DELETE button to remove items',
    language: 'text',
    expectLow: true,
    note: 'UI text in docs should not be flagged'
  }
];

let passed = 0;
let failed = 0;

for (const test of tests) {
  const result = scoreWithRules(test.code, test.language);
  const score = result.score;
  
  let success = false;
  if (test.expectLow) {
    success = score < 0.5;
  } else if (test.expectHigh) {
    success = score >= 0.6;
  }
  
  const status = success ? 'PASS:' : 'FAIL:';
  const color = success ? '\x1b[32m' : '\x1b[31m';
  const reset = '\x1b[0m';
  
  console.log(`${color}${status}${reset} ${test.name}`);
  console.log(`  Language: ${test.language}`);
  console.log(`  Score: ${score.toFixed(2)} ${test.expectLow ? '(expect < 0.5)' : '(expect >= 0.6)'}`);
  if (result.reasons.length > 0) {
    console.log(`  Reasons: ${result.reasons.slice(0, 3).join(', ')}`);
  }
  console.log(`  Note: ${test.note}`);
  console.log();
  
  if (success) {
    passed++;
  } else {
    failed++;
  }
}

console.log(`Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
