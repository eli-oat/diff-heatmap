const { parseDiff, scoreAllLines } = require('../diff-heatmap.js')
const { test, assert, assertBetween, printSummary } = require('./test-utils.js')

console.log('\n=== Large Change Detection Tests ===\n')

// Test 1: Single line change (baseline - should have low score)
test('Single line change has low/no large change score', () => {
  const diff = `diff --git a/test.js b/test.js
index 1234567..abcdefg 100644
--- a/test.js
+++ b/test.js
@@ -1,5 +1,5 @@
 const a = 1
 const b = 2
-const c = 3
+const c = 4
 const d = 5
 const e = 6`

  const parsed = parseDiff(diff)
  const scored = scoreAllLines(parsed)
  const addedLine = scored.find(l => l.tag === 'Added')
  
  // Single line changes should not trigger large change detection
  assert(addedLine.score < 0.5, `Expected low score for single line, got ${addedLine.score}`)
  assert(!addedLine.reasons.some(r => r.includes('consecutive') || r.includes('bulk')), 
    'Should not flag as large change')
})

// Test 2: Large consecutive block of additions (10+ lines)
test('Large consecutive additions get flagged', () => {
  const diff = `diff --git a/test.js b/test.js
index 1234567..abcdefg 100644
--- a/test.js
+++ b/test.js
@@ -1,3 +1,15 @@
 const setup = () => {
+  const line1 = 'added'
+  const line2 = 'added'
+  const line3 = 'added'
+  const line4 = 'added'
+  const line5 = 'added'
+  const line6 = 'added'
+  const line7 = 'added'
+  const line8 = 'added'
+  const line9 = 'added'
+  const line10 = 'added'
+  const line11 = 'added'
+  const line12 = 'added'
   return true
 }`

  const parsed = parseDiff(diff)
  const scored = scoreAllLines(parsed)
  const addedLines = scored.filter(l => l.tag === 'Added')
  
  // Check a line in the middle of the large addition
  const middleLine = addedLines[6] // 7th added line
  
  // Should detect bulk addition
  console.log(`  Score: ${middleLine.score.toFixed(2)}`)
  console.log(`  Reasons: ${middleLine.reasons.join(', ')}`)
  assert(middleLine.score >= 0.4, `Expected score >= 0.4 for bulk addition, got ${middleLine.score}`)
  assert(middleLine.reasons.some(r => r.toLowerCase().includes('addition') || r.toLowerCase().includes('consecutive')), 
    'Should flag as bulk addition')
})

// Test 3: Function rewrite (remove old + add new)
test('Function rewrite detected (remove + add pattern)', () => {
  const diff = `diff --git a/test.js b/test.js
index 1234567..abcdefg 100644
--- a/test.js
+++ b/test.js
@@ -1,8 +1,10 @@
-function oldImplementation(x) {
-  const a = x * 2
-  const b = a + 5
-  const c = b - 3
-  return c
-}
+function newImplementation(x, y) {
+  const result = x * y
+  const adjusted = result + 10
+  const final = adjusted - 5
+  const validated = final > 0 ? final : 0
+  return validated
+}
+
 export default oldImplementation`

  const parsed = parseDiff(diff)
  const scored = scoreAllLines(parsed)
  const addedLines = scored.filter(l => l.tag === 'Added')
  const removedLines = scored.filter(l => l.tag === 'Removed')
  
  // Should detect both removes and adds
  assert(addedLines.length > 5, 'Should have multiple added lines')
  assert(removedLines.length > 5, 'Should have multiple removed lines')
  
  // Check an added line in the middle of the new function
  const middleLine = addedLines[3]
  
  console.log(`  Score: ${middleLine.score.toFixed(2)}`)
  console.log(`  Reasons: ${middleLine.reasons.join(', ')}`)
  assert(middleLine.score >= 0.4, `Expected score >= 0.4 for function rewrite, got ${middleLine.score}`)
})

// Test 4: Bulk refactoring (high change density)
test('Bulk refactoring with high change density', () => {
  const diff = `diff --git a/config.js b/config.js
index 1234567..abcdefg 100644
--- a/config.js
+++ b/config.js
@@ -1,15 +1,15 @@
 export const config = {
-  oldKey1: 'value1',
-  oldKey2: 'value2',
-  oldKey3: 'value3',
+  newKey1: 'value1',
+  newKey2: 'value2', 
+  newKey3: 'value3',
   unchanged: 'same',
-  oldKey4: 'value4',
-  oldKey5: 'value5',
+  newKey4: 'value4',
+  newKey5: 'value5',
   alsoSame: 'same',
-  oldKey6: 'value6',
-  oldKey7: 'value7',
-  oldKey8: 'value8'
+  newKey6: 'value6',
+  newKey7: 'value7',
+  newKey8: 'value8'
 }`

  const parsed = parseDiff(diff)
  const scored = scoreAllLines(parsed)
  const addedLines = scored.filter(l => l.tag === 'Added')
  
  // Pick a line from high-density change area
  const testLine = addedLines[4]
  
  console.log(`  Score: ${testLine.score.toFixed(2)}`)
  console.log(`  Reasons: ${testLine.reasons.join(', ')}`)
  assert(testLine.score >= 0.3, `Expected score >= 0.3 for high density change, got ${testLine.score}`)
})

// Test 5: Isolated small change should NOT trigger
test('Small isolated change does not trigger large change detection', () => {
  const diff = `diff --git a/utils.js b/utils.js
index 1234567..abcdefg 100644
--- a/utils.js
+++ b/utils.js
@@ -10,7 +10,9 @@ function helper() {
 }
 
 function main() {
+  // Added small comment
   return helper()
+  // Another small comment
 }`

  const parsed = parseDiff(diff)
  const scored = scoreAllLines(parsed)
  const addedLines = scored.filter(l => l.tag === 'Added')
  
  for (const addedLine of addedLines) {
    // Small additions shouldn't trigger large change flags
    const hasLargeChangeReason = addedLine.reasons.some(r => 
      r.toLowerCase().includes('consecutive') || 
      r.toLowerCase().includes('bulk') ||
      r.toLowerCase().includes('large')
    )
    assert(!hasLargeChangeReason, `Line "${addedLine.text}" should not be flagged as large change`)
  }
})

// Test 6: Verify scored lines include change statistics
test('Scored lines should reflect change statistics', () => {
  const diff = `diff --git a/test.js b/test.js
index 1234567..abcdefg 100644
--- a/test.js
+++ b/test.js
@@ -1,3 +1,8 @@
+const a = 1
+const b = 2
+const c = 3
+const d = 4
+const e = 5
 const existing = true`

  const parsed = parseDiff(diff)
  const scored = scoreAllLines(parsed)
  const addedLines = scored.filter(l => l.tag === 'Added')
  
  // Should have scored the added lines
  assert(addedLines.length === 5, `Expected 5 added lines, got ${addedLines.length}`)
  
  // At least one should have a score from consecutive additions
  const hasConsecutiveScore = addedLines.some(l => 
    l.reasons.some(r => r.toLowerCase().includes('addition'))
  )
  
  console.log(`  First added line score: ${addedLines[0].score.toFixed(2)}`)
  console.log(`  First added line reasons: ${addedLines[0].reasons.join(', ')}`)
  
  assert(hasConsecutiveScore || addedLines[0].score >= 0.4, 
    'Should detect multi-line addition')
})

printSummary()
