#!/usr/bin/env node

/**
 * Test: SQL Injection Pattern False Positives
 * 
 * This test verifies that common false positives are reduced while
 * still catching actual SQL injection vulnerabilities.
 */

const { scoreWithRules } = require('../diff-heatmap.js');

const tests = [
  // False positives - should have LOW or ZERO scores
  {
    name: 'Plain text with "select"',
    code: 'const message = "Please select an option"',
    expectLow: true
  },
  {
    name: 'Plain text with "delete"',
    code: 'const text = "Click to delete your account"',
    expectLow: true
  },
  {
    name: 'Plain text with "update"',
    code: 'const help = "You can update your profile"',
    expectLow: true
  },
  {
    name: 'Function name with select',
    code: 'function selectBestOption() { }',
    expectLow: true
  },
  {
    name: 'Variable name with delete',
    code: 'const deleteHandler = () => {}',
    expectLow: true
  },
  
  // True positives - should have HIGH scores
  {
    name: 'Template literal SQL with interpolation',
    code: 'const query = `SELECT * FROM users WHERE id = ${userId}`',
    expectHigh: true
  },
  {
    name: 'String concatenation with FROM',
    code: 'const sql = "SELECT name FROM " + tableName',
    expectHigh: true
  },
  {
    name: 'INSERT with template literal',
    code: 'const insert = `INSERT INTO logs VALUES (${data})`',
    expectHigh: true
  },
  {
    name: 'DELETE with interpolation',
    code: 'const del = `DELETE FROM users WHERE id = ${id}`',
    expectHigh: true
  },
  {
    name: 'UPDATE with template literal',
    code: 'db.query(`UPDATE users SET name = \'${name}\'`)',
    expectHigh: true
  },
  
  // Edge cases - acceptable to flag or not flag
  {
    name: 'Static SQL query (no interpolation)',
    code: 'db.query("SELECT * FROM users")',
    expectLow: false, // May flag, but that's okay
    note: 'Static queries may still be flagged - this is acceptable'
  }
];

console.log('Testing SQL Injection Pattern Detection\n');

let passed = 0;
let failed = 0;

for (const test of tests) {
  const result = scoreWithRules(test.code, 'javascript');
  const score = result.score;
  
  let success = false;
  if (test.expectLow) {
    success = score < 0.5; // Low score expected
  } else if (test.expectHigh) {
    success = score >= 0.6; // High score expected
  } else {
    success = true; // Don't care
  }
  
  const status = success ? 'PASS:' : 'FAIL:';
  const color = success ? '\x1b[32m' : '\x1b[31m';
  const reset = '\x1b[0m';
  
  console.log(`${color}${status}${reset} ${test.name}`);
  console.log(`  Score: ${score.toFixed(2)} ${test.expectLow ? '(expect < 0.5)' : test.expectHigh ? '(expect >= 0.6)' : '(no expectation)'}`);
  if (result.reasons.length > 0) {
    console.log(`  Reasons: ${result.reasons.join(', ')}`);
  }
  if (test.note) {
    console.log(`  Note: ${test.note}`);
  }
  console.log();
  
  if (success) {
    passed++;
  } else {
    failed++;
  }
}

console.log(`Results: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
