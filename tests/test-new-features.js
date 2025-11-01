#!/usr/bin/env node

const {
  detectLanguage,
  scoreWithRules,
  parseSideBySide,
  renderDiffHTML,
  renderSideBySideHTML,
  parseDiff,
  scoreLine,
  RULES
} = require('../diff-heatmap.js')

const fs = require('fs')

let passCount = 0
let failCount = 0

function assert(condition, message) {
  if (condition) {
    passCount++
    console.log(`PASS: ${message}`)
  } else {
    failCount++
    console.error(`FAIL: ${message}`)
    console.error(`  Expected: true, Got: ${condition}`)
  }
}

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    passCount++
    console.log(`PASS: ${message}`)
  } else {
    failCount++
    console.error(`FAIL: ${message}`)
    console.error(`  Expected: ${expected}, Got: ${actual}`)
  }
}

function assertContains(text, substring, message) {
  assert(text.includes(substring), message)
}

function assertMatches(text, regex, message) {
  assert(regex.test(text), message)
}

console.log('\n=== Language Detection Tests ===\n')

assertEqual(detectLanguage('file.js'), 'javascript', 'Detects .js as javascript')
assertEqual(detectLanguage('file.jsx'), 'javascript', 'Detects .jsx as javascript')
assertEqual(detectLanguage('file.ts'), 'typescript', 'Detects .ts as typescript')
assertEqual(detectLanguage('file.tsx'), 'typescript', 'Detects .tsx as typescript')
assertEqual(detectLanguage('file.py'), 'python', 'Detects .py as python')
assertEqual(detectLanguage('file.rb'), 'ruby', 'Detects .rb as ruby')
assertEqual(detectLanguage('file.go'), 'go', 'Detects .go as go')
assertEqual(detectLanguage('file.rs'), 'rust', 'Detects .rs as rust')
assertEqual(detectLanguage('file.php'), 'php', 'Detects .php as php')
assertEqual(detectLanguage('file.java'), 'java', 'Detects .java as java')
assertEqual(detectLanguage('file.c'), 'c', 'Detects .c as c')
assertEqual(detectLanguage('file.cpp'), 'cpp', 'Detects .cpp as cpp')
assertEqual(detectLanguage('file.unknown'), 'unknown', 'Returns unknown for unrecognized extensions')

// === Rules System Tests ===

console.log('\n=== Rules System Tests ===\n')

// Test that RULES object exists and has expected structure
assert(typeof RULES === 'object', 'RULES object exists')
assert(RULES.secrets !== undefined, 'RULES has secrets category')
assert(RULES.dangerous_functions !== undefined, 'RULES has dangerous_functions category')
assert(RULES.sql_injection !== undefined, 'RULES has sql_injection category')

// Test rule structure
assert(RULES.secrets.score > 0, 'Secrets rule has score')
assert(RULES.secrets.patterns.length > 0, 'Secrets rule has patterns')
assert(RULES.secrets.patterns[0].regex instanceof RegExp, 'Pattern has regex')
assert(typeof RULES.secrets.patterns[0].desc === 'string', 'Pattern has description')

// === Score With Rules Tests ===

console.log('\n=== Score With Rules Tests ===\n')

// Test secret detection
const secretText = 'const apiKey = "sk-1234567890abcdefghijklmnopqrstuvwxyz"'
const secretScore = scoreWithRules(secretText).score
assert(secretScore >= 0.8, 'Secrets get high score via rules')

// Test dangerous functions
const evalText = 'const result = eval(userInput)'
const evalScore = scoreWithRules(evalText, 'javascript').score
assert(evalScore >= 0.8, 'eval() gets high score via rules')

// Test SQL injection
const sqlText = 'const query = "SELECT * FROM users WHERE id = " + userId'
const sqlScore = scoreWithRules(sqlText).score
assert(sqlScore >= 0.7, 'SQL injection patterns get high score')

// Test language-specific rules
const pythonUnsafe = 'pickle.loads(data)'
const pythonScore = scoreWithRules(pythonUnsafe, 'python').score
assert(pythonScore >= 0.6, 'Python-specific rules apply to Python code')

const rustUnsafe = 'value.unwrap()'
const rustScore = scoreWithRules(rustUnsafe, 'rust').score
assert(rustScore >= 0.6, 'Rust-specific rules apply to Rust code')

// Test that language-specific rules don't apply to wrong language
const pythonOnJS = scoreWithRules(pythonUnsafe, 'javascript').score
const rustOnJS = scoreWithRules(rustUnsafe, 'javascript').score
// These should be 0 or very low since the rules are language-specific
assert(pythonOnJS < pythonScore, 'Python-specific rules score lower on JS')
assert(rustOnJS < rustScore, 'Rust-specific rules score lower on JS')

// === Side-by-Side Parser Tests ===

console.log('\n=== Side-by-Side Parser Tests ===\n')

const simpleDiff = `diff --git a/test.js b/test.js
index 1234567..abcdefg 100644
--- a/test.js
+++ b/test.js
@@ -1,3 +1,4 @@
 function test() {
+  const x = 10
   return true
 }`

const parsed = parseSideBySide(simpleDiff)
assert(Array.isArray(parsed), 'parseSideBySide returns array')
assert(parsed.length > 0, 'parseSideBySide returns files')
assert(parsed[0].hunks !== undefined, 'Parsed file has hunks')
assert(parsed[0].hunks.length > 0, 'Parsed file has at least one hunk')
assert(parsed[0].hunks[0].lines !== undefined, 'Hunk has lines')

// Check line structure
const lines = parsed[0].hunks[0].lines
assert(lines.length > 0, 'Hunk has parsed lines')
assert(lines[0].type !== undefined, 'Line has type')
assert(typeof lines[0].leftNum === 'number' || lines[0].leftNum === null, 'Line has leftNum')
assert(typeof lines[0].rightNum === 'number' || lines[0].rightNum === null, 'Line has rightNum')

// Check that added lines have rightNum but no leftNum
const addedLine = lines.find(l => l.type === 'added')
if (addedLine) {
  assert(addedLine.leftNum === null, 'Added line has no left line number')
  assert(addedLine.rightNum !== null, 'Added line has right line number')
}

// === HTML Generation Tests ===

console.log('\n=== HTML Rendering Tests ===\n')

// Test unified HTML view
const diffLines = parseDiff(simpleDiff)
const scoredLines = diffLines.map((line, i) => {
  if (line.tag === 'Added') {
    const context = { prev: [], next: [], indent: 0 }
    const result = scoreLine(line.text, context)
    return { ...line, score: result.score, reasons: result.reasons }
  }
  return line
})

const unifiedHTML = renderDiffHTML(scoredLines)
assertContains(unifiedHTML, '<div class="container">', 'Unified HTML has container')
assertContains(unifiedHTML, '<table', 'Unified HTML has table')
assertContains(unifiedHTML, 'class="line-num"', 'Unified HTML has line numbers')
assertContains(unifiedHTML, 'line-content', 'Unified HTML has line content')
assertContains(unifiedHTML, 'diff --git', 'Unified HTML preserves diff header')

// Test side-by-side HTML view
const sideHTML = renderSideBySideHTML(simpleDiff)
assertContains(sideHTML, '<div class="container">', 'Side-by-side HTML has container')
assertContains(sideHTML, '<table', 'Side-by-side HTML has table')
assertContains(sideHTML, 'left-panel', 'Side-by-side HTML has left panel')
assertContains(sideHTML, 'right-panel', 'Side-by-side HTML has right panel')
assertContains(sideHTML, 'diff-panels', 'Side-by-side HTML has panel wrapper')
assertContains(sideHTML, 'line-num', 'Side-by-side HTML has line numbers')

// === Complex Diff Tests ===

console.log('\n=== Complex Diff Tests ===\n')

// Test with comprehensive diff
const testDiffPath = __dirname + '/test-comprehensive.diff'
if (fs.existsSync(testDiffPath)) {
  const testDiff = fs.readFileSync(testDiffPath, 'utf8')
  
  // Test side-by-side parsing
  const parsedFiles = parseSideBySide(testDiff)
  assert(parsedFiles.length > 0, 'Comprehensive diff parsed successfully')
  
  // Test that all lines have proper structure
  let lineCount = 0
  for (const file of parsedFiles) {
    for (const hunk of file.hunks) {
      for (const line of hunk.lines) {
        lineCount++
        assert(line.type !== undefined, `Line ${lineCount} has type`)
        assert(line.content !== undefined, `Line ${lineCount} has content`)
      }
    }
  }
  console.log(`PASS: Processed ${lineCount} lines from comprehensive diff`)
  
  // Test HTML generation with comprehensive diff
  const compUnifiedHTML = renderDiffHTML(parseDiff(testDiff).map((line, i) => {
    if (line.tag === 'Added') {
      const context = { prev: [], next: [], indent: 0 }
      const result = scoreLine(line.text, context)
      return { ...line, score: result.score, reasons: result.reasons }
    }
    return line
  }))
  assert(compUnifiedHTML.length > 1000, 'Comprehensive unified HTML is substantial')
  assertContains(compUnifiedHTML, 'hl-secret', 'Comprehensive HTML has secret highlights')
  assertContains(compUnifiedHTML, 'hl-danger', 'Comprehensive HTML has danger highlights')
  
  const compSideHTML = renderSideBySideHTML(testDiff)
  assert(compSideHTML.length > 1000, 'Comprehensive side-by-side HTML is substantial')
  assertContains(compSideHTML, 'data-row=', 'Side-by-side has row tracking')
}

// === Integration: Language-Aware Scoring ===

console.log('\n=== Language-Aware Integration Tests ===\n')

// Create diff with language hints
const jsDiff = `diff --git a/app.js b/app.js
@@ -1,1 +1,2 @@
 function test() {
+  var x = 10
 }`

const pyDiff = `diff --git a/app.py b/app.py
@@ -1,1 +1,2 @@
 def test():
+  except:
 }`

const rsDiff = `diff --git a/app.rs b/app.rs
@@ -1,1 +1,2 @@
 fn test() {
+  value.unwrap()
 }`

// Note: Current implementation doesn't auto-detect language from filename in scoring
// This is a feature we could add in the future
const jsLines = parseDiff(jsDiff)
const pyLines = parseDiff(pyDiff)
const rsLines = parseDiff(rsDiff)

assert(jsLines.length > 0, 'JS diff parsed')
assert(pyLines.length > 0, 'Python diff parsed')
assert(rsLines.length > 0, 'Rust diff parsed')

// === Edge Cases ===

console.log('\n=== Edge Case Tests ===\n')

// Test empty diff
const emptyParsed = parseSideBySide('')
assert(Array.isArray(emptyParsed), 'Empty diff returns array')

// Test diff with only headers
const headerOnlyDiff = `diff --git a/test.js b/test.js
index 1234567..abcdefg 100644
--- a/test.js
+++ b/test.js`

const headerParsed = parseSideBySide(headerOnlyDiff)
assert(Array.isArray(headerParsed), 'Header-only diff returns array')

// Test diff with removals only
const removalDiff = `diff --git a/test.js b/test.js
@@ -1,2 +1,1 @@
 function test() {
-  const x = 10
 }`

const removalParsed = parseSideBySide(removalDiff)
assert(removalParsed.length > 0, 'Removal-only diff parsed')
const removalLine = removalParsed[0]?.hunks[0]?.lines.find(l => l.type === 'removed')
if (removalLine) {
  assert(removalLine.leftNum !== null, 'Removed line has left line number')
  assert(removalLine.rightNum === null, 'Removed line has no right line number')
}

console.log('\n=== Test Summary ===\n')
console.log(`Passed: ${passCount}`)
console.log(`Failed: ${failCount}`)
console.log(`Total:  ${passCount + failCount}`)

if (failCount === 0) {
  console.log('\nSUCCESS: All tests passed!')
  process.exit(0)
} else {
  console.log(`\nERROR: ${failCount} test(s) failed`)
  process.exit(1)
}
