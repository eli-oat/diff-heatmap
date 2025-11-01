#!/usr/bin/env node

const { scoreLine, scoreWithRules } = require('../diff-heatmap.js')
const { assert, assertBetween } = require('./test-utils')

console.log('=== Score Stacking Tests ===\n');

// Non-isolated context to avoid the +0.3 isolated change bonus
const context = { prev: ['line before'], next: ['line after'], indent: 0 };

// Test 1: Single high-severity pattern
const singlePattern = scoreLine('const API_KEY = "sk-test";', context, 'javascript');
assert(singlePattern.score === 0.9, 'Single pattern gets full score (0.9)');
assert(singlePattern.reasons.length === 1, 'Single pattern has 1 reason');

// Test 2: Two high-severity patterns (same score)
const twoPatterns = scoreLine('const API_KEY = "sk-test"; eval(API_KEY);', context, 'javascript');
assertBetween(twoPatterns.score, 1.0, 1.0, 'Two patterns stack to cap (0.9 + 0.9*0.5 = 1.35 → 1.0)');
assert(twoPatterns.reasons.length === 2, 'Two patterns have 2 reasons');
assert(twoPatterns.reasons.includes('Credential assignments'), 'Includes first pattern reason');
assert(twoPatterns.reasons.includes('Code execution'), 'Includes second pattern reason');

// Test 3: Pattern + complexity
const patternAndComplexity = scoreLine(
  'const password = "test"; if (a && b && c && d && e && f) { }',
  context,
  'javascript'
);
assertBetween(patternAndComplexity.score, 0.95, 1.0, 'Pattern (0.9) + complexity (0.8) stacks');
assert(patternAndComplexity.reasons.length > 2, 'Has pattern and complexity reasons');

// Test 4: Different severity patterns
const diffSeverity = scoreLine(
  'fetch(url); eval(data);',
  context,
  'javascript'
);
// fetch = 0.5, eval = 0.85, stacking: 0.85 + 0.5*0.5 = 1.10 → 1.0
assertBetween(diffSeverity.score, 1.0, 1.0, 'Different severity patterns stack (0.85 + 0.5*0.5)');

// Test 5: Single medium-severity pattern (no stacking)
const mediumPattern = scoreLine('fetch("/api/data");', context, 'javascript');
assertBetween(mediumPattern.score, 0.5, 0.5, 'Single medium pattern (0.5)');

// Test 6: Complexity only
const complexityOnly = scoreLine('if (a && b && c && d && e && f) { }', context, 'javascript');
// Multiple complexity reasons but single complexity score
assertBetween(complexityOnly.score, 0.8, 1.0, 'Complexity generates high score');

// Test 7: Normal code (no stacking, zero score)
const normalCode = scoreLine('const x = 10;', context, 'javascript');
assert(normalCode.score === 0, 'Normal code scores 0');
assert(normalCode.reasons.length === 0, 'Normal code has no reasons');

// Test 8: Three patterns
const threePatterns = scoreLine(
  'const API_KEY = "sk-test"; eval(API_KEY); exec(cmd);',
  context,
  'javascript'
);
assertBetween(threePatterns.score, 1.0, 1.0, 'Three patterns hit cap');
assert(threePatterns.reasons.length >= 2, 'Three patterns have multiple reasons');

// Test 9: Multiple patterns in same rule (should NOT stack scores, just reasons)
const sameRulePatterns = scoreLine(
  'const x = a == b || c === d',
  context,
  'javascript'
);
// Loose equality (0.7) + Multiple logical operators (0.6)
// These are different rules, so: 0.7 + 0.6*0.5 = 1.0
assertBetween(sameRulePatterns.score, 0.7, 1.0, 'Multiple matching rules stack');

// Test 10: Verify scoreWithRules stacking at rule level
const rulesResult = scoreWithRules('const password = "test"; eval(password);', 'javascript');
assertBetween(rulesResult.score, 1.0, 1.0, 'scoreWithRules stacks multiple rules');
assert(rulesResult.reasons.length === 2, 'scoreWithRules collects all reasons');

// Test 11: Isolated change bonus stacking
const isolated = scoreLine('const API_KEY = "sk-test";', { prev: [], next: [], indent: 0 }, 'javascript');
assertBetween(isolated.score, 1.0, 1.0, 'Isolated change adds to score (0.9 + 0.3*0.5)');
assert(isolated.reasons.includes('Isolated change'), 'Isolated change adds reason');

require('./test-utils').printSummary()
