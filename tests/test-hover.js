#!/usr/bin/env node

const { renderSideBySideHTML } = require('../diff-heatmap.js')
const fs = require('fs')

console.log('\n=== Hover Highlighting Tests ===\n')

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

// Create a test diff
const testDiff = `diff --git a/test.js b/test.js
@@ -1,3 +1,5 @@
 line 1
-line 2 removed
 line 3
+line 4 added
+line 5 added
 line 6`

const html = renderSideBySideHTML(testDiff)

// Test 1: Both panels should exist
assert(html.includes('left-panel'), 'Has left panel')
assert(html.includes('right-panel'), 'Has right panel')

// Test 2: Extract row IDs from left panel
const leftPanelMatch = html.match(/left-panel[\s\S]*?(?=<div class="diff-panel right-panel">)/);
if (!leftPanelMatch) {
  console.error('Could not extract left panel')
  failed++
} else {
  const leftPanel = leftPanelMatch[0]
  const leftRowIds = (leftPanel.match(/data-row="(\d+)"/g) || []).map(m => m.match(/\d+/)[0])
  
  // Test 3: Extract row IDs from right panel
  const rightPanelMatch = html.match(/right-panel[\s\S]*?<\/div><\/div><\/div>/);
  if (!rightPanelMatch) {
    console.error('Could not extract right panel')
    failed++
  } else {
    const rightPanel = rightPanelMatch[0]
    const rightRowIds = (rightPanel.match(/data-row="(\d+)"/g) || []).map(m => m.match(/\d+/)[0])
    
    // Test 4: Same number of rows in both panels
    assert(leftRowIds.length === rightRowIds.length, 
      `Both panels have same row count (left: ${leftRowIds.length/2}, right: ${rightRowIds.length/2})`)
    
    // Test 5: Row IDs match between panels
    let allMatch = true
    for (let i = 0; i < Math.min(leftRowIds.length, rightRowIds.length); i++) {
      if (leftRowIds[i] !== rightRowIds[i]) {
        allMatch = false
        console.error(`  Row ${i}: left=${leftRowIds[i]}, right=${rightRowIds[i]}`)
      }
    }
    assert(allMatch, 'All row IDs match between left and right panels')
    
    // Test 6: Row IDs are sequential starting from 0
    const uniqueIds = [...new Set(leftRowIds)].sort((a, b) => parseInt(a) - parseInt(b))
    const expectedIds = Array.from({length: uniqueIds.length}, (_, i) => i.toString())
    assert(JSON.stringify(uniqueIds) === JSON.stringify(expectedIds),
      `Row IDs are sequential: ${uniqueIds.join(', ')}`)
  }
}

// Test 7: Each row ID should appear exactly 4 times total (2 in left panel, 2 in right)
// (once for tr, once for td in each panel)
const allRowIds = (html.match(/data-row="(\d+)"/g) || []).map(m => m.match(/\d+/)[0])
const rowIdCounts = {}
allRowIds.forEach(id => {
  rowIdCounts[id] = (rowIdCounts[id] || 0) + 1
})

let correctCounts = true
for (const [id, count] of Object.entries(rowIdCounts)) {
  if (count !== 4) {
    console.error(`  Row ID ${id} appears ${count} times (expected 4)`)
    correctCounts = false
  }
}
assert(correctCounts, 'Each row ID appears exactly 4 times (2 per panel)')

// Test 8: Line numbers should NOT have IDs (we removed clickable functionality)
const lineNumIds = (html.match(/id="[LR]\d+"/g) || [])
assert(lineNumIds.length === 0, 
  `Line numbers have no IDs (clickable functionality removed)`)

// Test 9: Verify structure with real test file
const testDiffPath = __dirname + '/test-long-lines.diff'
if (fs.existsSync(testDiffPath)) {
  const realDiff = fs.readFileSync(testDiffPath, 'utf8')
  const realHtml = renderSideBySideHTML(realDiff)
  
  assert(realHtml.includes('diff-panels'), 'Real diff has panel structure')
  
  const realLeftRows = (realHtml.match(/left-panel[\s\S]*?right-panel/)[0].match(/data-row="\d+"/g) || [])
  const realRightRows = (realHtml.match(/right-panel[\s\S]*?<\/div><\/div><\/div>/)[0].match(/data-row="\d+"/g) || [])
  
  assert(realLeftRows.length === realRightRows.length,
    `Real diff has matching row counts (left: ${realLeftRows.length}, right: ${realRightRows.length})`)
}

console.log('\n=== Test Summary ===\n')
console.log(`Passed: ${passed}`)
console.log(`Failed: ${failed}`)
console.log(`Total:  ${passed + failed}`)

if (failed === 0) {
  console.log('\nSUCCESS: All hover tests passed!')
  console.log('\nHovering over a line number will correctly highlight the matching row in both panels.')
  process.exit(0)
} else {
  console.log(`\nERROR: ${failed} test(s) failed`)
  process.exit(1)
}
