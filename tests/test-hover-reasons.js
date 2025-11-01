#!/usr/bin/env node

/**
 * Test hover text functionality
 * Verifies that title attributes are correctly added with pattern descriptions
 */

const { execSync } = require('child_process');
const fs = require('fs');

const testCases = [
  {
    name: 'Secrets - API key',
    diff: `diff --git a/config.js b/config.js
--- a/config.js
+++ b/config.js
@@ -1,0 +1,1 @@
+const API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz";`,
    expectedReasons: ['Credential assignments']
  },
  {
    name: 'SQL Injection',
    diff: `diff --git a/query.py b/query.py
--- a/query.py
+++ b/query.py
@@ -1,0 +1,1 @@
+cursor.execute("SELECT * FROM users WHERE id = " + user_id)`,
    expectedReasons: ['SQL query structure']
  },
  {
    name: 'XSS - dangerouslySetInnerHTML',
    diff: `diff --git a/component.jsx b/component.jsx
--- a/component.jsx
+++ b/component.jsx
@@ -1,0 +1,1 @@
+return <div dangerouslySetInnerHTML={{__html: userInput}} />;`,
    expectedReasons: ['React dangerouslySetInnerHTML']
  },
  {
    name: 'Command Injection',
    diff: `diff --git a/exec.js b/exec.js
--- a/exec.js
+++ b/exec.js
@@ -1,0 +1,1 @@
+exec("ls -la " + userInput);`,
    expectedReasons: ['Code execution']
  },
  {
    name: 'Mutable State - Global let',
    diff: `diff --git a/state.js b/state.js
--- a/state.js
+++ b/state.js
@@ -1,0 +1,1 @@
+let globalCounter = 0;`,
    expectedReasons: ['Global mutable variable (JS)']
  },
  {
    name: 'Complexity - Multiple operators',
    diff: `diff --git a/logic.js b/logic.js
--- a/logic.js
+++ b/logic.js
@@ -1,0 +1,1 @@
+if (a > 5 && b < 10 || c === 20 && d !== 30 || e >= 40 && f <= 50) {`,
    expectedReasons: ['Complex expression']
  },
  {
    name: 'Code execution - eval',
    diff: `diff --git a/danger.js b/danger.js
--- a/danger.js
+++ b/danger.js
@@ -1,0 +1,1 @@
+eval("ls " + userInput);`,
    expectedReasons: ['Code execution']
  },
  {
    name: 'Multiple patterns in same line',
    diff: `diff --git a/test.js b/test.js
--- a/test.js
+++ b/test.js
@@ -1,0 +1,1 @@
+const password = "secret123"; eval(password);`,
    expectedReasons: ['Credential assignments', 'Code execution']
  }
];

let passed = 0;
let failed = 0;

console.log('Testing hover text functionality...\n');

for (const testCase of testCases) {
  try {
    // Generate HTML output
    const result = execSync('node diff-heatmap.js --html', {
      input: testCase.diff,
      encoding: 'utf8'
    });
    
    // Check if title attribute exists and contains expected reasons
    let testPassed = true;
    const missingReasons = [];
    
    for (const expectedReason of testCase.expectedReasons) {
      if (!result.includes(`title=`)) {
        testPassed = false;
        missingReasons.push('No title attribute found');
        break;
      }
      
      if (!result.includes(expectedReason)) {
        testPassed = false;
        missingReasons.push(expectedReason);
      }
    }
    
    if (testPassed) {
      console.log(`PASS: ${testCase.name}`);
      passed++;
    } else {
      console.log(`FAIL: ${testCase.name}`);
      console.log(`  Missing reasons: ${missingReasons.join(', ')}`);
      failed++;
    }
  } catch (error) {
    console.log(`FAIL: ${testCase.name} - Error: ${error.message}`);
    failed++;
  }
}

console.log('\n=== Test Summary ===\n');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed === 0) {
  console.log('\nSUCCESS: All hover text tests passed!\n');
  console.log('Hover over highlighted lines in HTML output to see pattern descriptions.');
  process.exit(0);
} else {
  console.log('\nERROR: Some tests failed');
  process.exit(1);
}
