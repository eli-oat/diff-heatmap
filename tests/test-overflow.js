#!/usr/bin/env node

const { renderSideBySideHTML, renderDiffHTML, parseDiff } = require('../diff-heatmap.js')
const fs = require('fs')

console.log('\n=== Overflow Prevention Tests ===\n')

let passed = 0
let failed = 0

function assert(condition, message) {
  if (condition) {
    passed++
    console.log(`PASS: ${message}`)
  } else {
    failed++
    console.error(`FAIL: ${message}`)
  }
}

// Create a diff with very long lines
const longLineDiff = `diff --git a/test.js b/test.js
@@ -1,1 +1,3 @@
 function test() {
+  const veryLongLine = "${'x'.repeat(200)}"
+  const apiKey = "sk-${'0123456789abcdef'.repeat(10)}"
 }`

// Test side-by-side view structure (content only, no CSS)
const sideHTML = renderSideBySideHTML(longLineDiff)
assert(sideHTML.includes('left-panel'), 'Side-by-side has left-panel')
assert(sideHTML.includes('right-panel'), 'Side-by-side has right-panel')
assert(sideHTML.includes('panel-table'), 'Side-by-side has panel tables')

// Test unified view structure (content only, no CSS)
const diffLines = parseDiff(longLineDiff).map(line => 
  line.tag === 'Added' ? {...line, score: 0.5} : line
)
const unifiedHTML = renderDiffHTML(diffLines)
assert(unifiedHTML.includes('line-content'), 'Unified view has line-content class')

// Generate full HTML pages and check they contain overflow fixes
const { execSync } = require('child_process')
const testDiffPath = __dirname + '/test-long-lines.diff'

if (fs.existsSync(testDiffPath)) {
  // Test side-by-side
  const sideOutput = execSync(`node ${__dirname}/../diff-heatmap.js ${testDiffPath} --side-by-side`, {
    encoding: 'utf8'
  })
  assert(sideOutput.includes('overflow-x: auto'), 'Full side-by-side page has overflow-x')
  assert(sideOutput.includes('overflow'), 'Full side-by-side page has overflow')
  
  // Test unified
  const unifiedOutput = execSync(`node ${__dirname}/../diff-heatmap.js ${testDiffPath} --html`, {
    encoding: 'utf8'
  })
  assert(unifiedOutput.includes('max-width: 0'), 'Full unified page has max-width')
  assert(unifiedOutput.includes('overflow-x: auto'), 'Full unified page has overflow-x')
}

console.log('\n=== Test Summary ===\n')
console.log(`Passed: ${passed}`)
console.log(`Failed: ${failed}`)
console.log(`Total:  ${passed + failed}`)

if (failed === 0) {
  console.log('\nSUCCESS: All overflow tests passed!')
  console.log('\nLong lines will now scroll within their cells instead of overflowing.')
  process.exit(0)
} else {
  console.log(`\nERROR: ${failed} test(s) failed`)
  process.exit(1)
}
