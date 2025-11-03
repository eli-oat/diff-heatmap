#!/usr/bin/env node

const { execSync } = require('child_process')
const path = require('path')

console.log('Running diff-heatmap test suite...\n')

const testFiles = [
  'test-critical-patterns.js',
  'test-mutable-state.js',
  'test-new-features.js',
  'test-regex-validation.js',
  'test-score-stacking.js',
  'test-sql-false-positives.js',
  'test-loose-equality.js',
  'test-markdown-docs.js',
  'test-hover.js',
  'test-hover-reasons.js',
  'test-overflow.js',
  'test-large-changes.js',
  'test-accessibility.js'
]

let totalPassed = 0
let totalFailed = 0
let allPassed = true

for (const testFile of testFiles) {
  console.log(`\n${'='.repeat(60)}`)
  console.log(`Running: ${testFile}`)
  console.log('='.repeat(60))
  
  try {
    const output = execSync(`node ${path.join(__dirname, testFile)}`, {
      encoding: 'utf8',
      stdio: 'pipe'
    })
    
    console.log(output)
    
    const passMatch = output.match(/Passed: (\d+)/)
    const failMatch = output.match(/Failed: (\d+)/)
    
    if (passMatch) totalPassed += parseInt(passMatch[1])
    if (failMatch) {
      const failed = parseInt(failMatch[1])
      totalFailed += failed
      if (failed > 0) allPassed = false
    }
    
  } catch (error) {
    console.error(`\nERROR: ${testFile} failed with error:`)
    console.error(error.stdout || error.message)
    allPassed = false
    totalFailed++
  }
}

console.log('\n' + '='.repeat(60))
console.log('OVERALL TEST SUMMARY')
console.log('='.repeat(60))
console.log(`Total Passed: ${totalPassed}`)
console.log(`Total Failed: ${totalFailed}`)
console.log(`Total Tests:  ${totalPassed + totalFailed}`)

if (allPassed) {
  console.log('\nAll test suites passed!')
  process.exit(0)
} else {
  console.log(`\nSome tests failed`)
  process.exit(1)
}
