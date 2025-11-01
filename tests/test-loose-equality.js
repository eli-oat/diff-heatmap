#!/usr/bin/env node

/**
 * Test: Loose Equality Pattern
 * 
 * Verifies that loose equality (==) and inequality (!=) are correctly detected
 * without false positives on strict equality (===, !==) or arrow functions (=>)
 */

const { scoreWithRules } = require('../diff-heatmap.js');

const tests = [
  // Should NOT trigger (strict equality)
  {
    name: 'Strict equality (===)',
    code: 'if (a === b) return true',
    shouldTrigger: false
  },
  {
    name: 'Strict inequality (!==)',
    code: 'if (x !== y) return false',
    shouldTrigger: false
  },
  {
    name: 'Arrow function (=>)',
    code: 'const fn = x => x * 2',
    shouldTrigger: false
  },
  {
    name: 'Arrow function with equality',
    code: 'items.filter(x => x === value)',
    shouldTrigger: false
  },
  
  // Should trigger (loose equality)
  {
    name: 'Loose equality (==)',
    code: 'if (a == b) return true',
    shouldTrigger: true,
    expectedReason: 'Loose equality'
  },
  {
    name: 'Loose inequality (!=)',
    code: 'if (x != y) return false',
    shouldTrigger: true,
    expectedReason: 'Loose inequality'
  },
  {
    name: 'Null check with ==',
    code: 'const isNull = value == null',
    shouldTrigger: true,
    expectedReason: 'Loose equality'
  },
  {
    name: 'Zero check with ==',
    code: 'return count == 0',
    shouldTrigger: true,
    expectedReason: 'Loose equality'
  },
  {
    name: 'Undefined check with !=',
    code: 'if (obj != undefined) { }',
    shouldTrigger: true,
    expectedReason: 'Loose inequality'
  }
];

console.log('Testing Loose Equality Pattern Detection\n');

let passed = 0;
let failed = 0;

for (const test of tests) {
  const result = scoreWithRules(test.code, 'javascript');
  const hasLooseEquality = result.reasons.some(r => 
    r.includes('Loose equality') || r.includes('Loose inequality')
  );
  
  let success = false;
  if (test.shouldTrigger) {
    success = hasLooseEquality;
  } else {
    success = !hasLooseEquality;
  }
  
  const status = success ? 'PASS:' : 'FAIL:';
  const color = success ? '\x1b[32m' : '\x1b[31m';
  const reset = '\x1b[0m';
  
  console.log(`${color}${status}${reset} ${test.name}`);
  if (hasLooseEquality) {
    const looseReasons = result.reasons.filter(r => 
      r.includes('Loose equality') || r.includes('Loose inequality')
    );
    console.log(`  Found: ${looseReasons.join(', ')}`);
  }
  if (!success) {
    if (test.shouldTrigger) {
      console.log(`  Expected to trigger but didn't`);
    } else {
      console.log(`  Should NOT trigger but did`);
    }
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
