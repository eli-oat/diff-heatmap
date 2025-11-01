let passed = 0
let failed = 0
const failures = []

function test(description, fn) {
  try {
    fn()
    console.log(`PASS: ${description}`)
    passed++
  } catch (err) {
    console.log(`FAIL: ${description}`)
    console.log(`  Error: ${err.message}`)
    failed++
    failures.push({ description, error: err.message })
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed')
  }
}

function assertBetween(value, min, max, message) {
  if (value >= min && value <= max) {
    passed++
    console.log(`PASS: ${message} (${value.toFixed(2)})`)
  } else {
    failed++
    console.error(`FAIL: ${message} (expected ${min}-${max}, got ${value.toFixed(2)})`)
    failures.push({ description: message, error: `Expected ${min}-${max}, got ${value.toFixed(2)}` })
  }
}

function printSummary() {
  console.log('\n=== Test Summary ===\n')
  console.log(`Passed: ${passed}`)
  console.log(`Failed: ${failed}`)
  console.log(`Total:  ${passed + failed}`)

  if (failed > 0) {
    console.log('\n--- Failed Tests ---')
    failures.forEach(f => {
      console.log(`\n${f.description}`)
      console.log(`  ${f.error}`)
    })
    console.log(`\n${failed} test(s) failed`)
    process.exit(1)
  } else {
    console.log('\nAll tests passed!')
    process.exit(0)
  }
}

module.exports = {
  test,
  assert,
  assertBetween,
  printSummary
}
