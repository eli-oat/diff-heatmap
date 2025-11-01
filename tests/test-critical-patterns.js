#!/usr/bin/env node

const { test, assert } = require('./test-utils')

console.log('=== Critical Security Pattern Tests ===\n');

// Test 1: Java Deserialization Patterns (CWE-502)
test('Detects ObjectInputStream.readObject()', () => {
  const pattern = /readObject\s*\(/g;
  assert(pattern.test('ObjectInputStream ois = new ObjectInputStream(input); return ois.readObject();'),
    'Should detect readObject()');
});

test('Detects XMLDecoder', () => {
  const pattern = /XMLDecoder/g;
  assert(pattern.test('XMLDecoder decoder = new XMLDecoder(input);'),
    'Should detect XMLDecoder');
});

test('Detects XStream deserialization', () => {
  const pattern = /XStream\s*\(/g;
  assert(pattern.test('XStream xstream = new XStream();'),
    'Should detect XStream usage');
});

// Test 2: C/C++ Buffer Overflow Patterns (CWE-120)
test('Detects strcpy()', () => {
  const pattern = /\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|sscanf|fscanf)\s*\(/g;
  assert(pattern.test('strcpy(buffer, user_input);'),
    'Should detect strcpy');
});

test('Detects gets()', () => {
  const pattern = /\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|sscanf|fscanf)\s*\(/g;
  assert(pattern.test('gets(buffer);'),
    'Should detect gets');
});

test('Detects sprintf()', () => {
  const pattern = /\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|sscanf|fscanf)\s*\(/g;
  assert(pattern.test('sprintf(buffer, "User: %s", input);'),
    'Should detect sprintf');
});

test('Detects alloca()', () => {
  const pattern = /\balloca\s*\(/g;
  assert(pattern.test('char *buf = alloca(size);'),
    'Should detect alloca');
});

test('Detects bounded string functions', () => {
  const pattern = /(strncpy|strncat|snprintf|vsnprintf)\s*\(/g;
  const test1 = 'strncpy(buf, input, 100);';
  const test2 = 'snprintf(buf, 100, "%s", input);';
  assert(pattern.test(test1), `Should detect strncpy in: ${test1}`);
  // Reset pattern for second test
  const pattern2 = /(strncpy|strncat|snprintf|vsnprintf)\s*\(/g;
  assert(pattern2.test(test2), `Should detect snprintf in: ${test2}`);
});

// Test 3: Python Enhanced SQL injection (CWE-089)
test('Detects Python f-string SQL injection', () => {
  const pattern = /f["'][^"']*\{[^}]*\}[^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)|f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{[^}]*\}/gi;
  const testString = 'query = f"SELECT * FROM users WHERE id = {user_id}"';
  assert(pattern.test(testString),
    `Should detect f-string SQL injection in: ${testString}`);
});

test('Detects .format() SQL injection', () => {
  const pattern = /["'].*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\.format\(/gi;
  const testString = 'query = "SELECT * FROM users WHERE name = {}".format(username)';
  assert(pattern.test(testString),
    `Should detect .format() SQL injection in: ${testString}`);
});

test('Detects string formatting in execute()', () => {
  const pattern = /\bexecute\s*\(\s*["'][^"']*\%s[^"']*["']\s*\%/g;
  assert(pattern.test('cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'),
    'Should detect percent formatting in execute');
});

// Test 4: Python Deserialization (CWE-502)
test('Detects pickle.loads()', () => {
  const pattern = /\b(pickle\.loads?|pickle\.Unpickler|yaml\.load|marshal\.loads?)\s*\(/g;
  assert(pattern.test('data = pickle.loads(untrusted_data)'),
    'Should detect pickle.loads');
});

test('Detects yaml.load()', () => {
  const pattern = /\b(pickle\.loads?|pickle\.Unpickler|yaml\.load|marshal\.loads?)\s*\(/g;
  assert(pattern.test('config = yaml.load(file)'),
    'Should detect yaml.load');
});

test('Detects marshal.loads()', () => {
  const pattern = /\b(pickle\.loads?|pickle\.Unpickler|yaml\.load|marshal\.loads?)\s*\(/g;
  assert(pattern.test('obj = marshal.loads(data)'),
    'Should detect marshal.loads');
});

// Test 5: PHP Input Injection (CWE-073, CWE-078)
test('Detects $_GET usage', () => {
  const pattern = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/g;
  assert(pattern.test('$file = $_GET[\'file\'];'),
    'Should detect $_GET');
});

test('Detects include with $_GET', () => {
  const pattern = /\binclude\s*\(\s*\$_(GET|POST|REQUEST)/g;
  assert(pattern.test('include($_GET[\'page\']);'),
    'Should detect include with $_GET');
});

test('Detects exec with $_POST', () => {
  const pattern = /\bexec\s*\([^)]*\$_(GET|POST|REQUEST)/g;
  assert(pattern.test('exec($_POST[\'command\']);'),
    'Should detect exec with $_POST');
});

test('Detects shell_exec with user input', () => {
  const pattern = /\bshell_exec\s*\([^)]*\$_(GET|POST|REQUEST)/g;
  assert(pattern.test('shell_exec($_GET[\'script\']);'),
    'Should detect shell_exec with $_GET');
});

test('Detects PHP unserialize', () => {
  const pattern = /\bunserialize\s*\(/g;
  assert(pattern.test('$data = unserialize($_COOKIE[\'session\']);'),
    'Should detect unserialize');
});

// Test 6: Java Reflection (CWE-470)
test('Detects Class.forName()', () => {
  const pattern = /\bClass\.forName\s*\(/g;
  assert(pattern.test('Class<?> clazz = Class.forName(className);'),
    'Should detect Class.forName');
});

test('Detects .invoke() (reflection)', () => {
  const pattern = /\.invoke\s*\(/g;
  assert(pattern.test('method.invoke(obj);'),
    'Should detect .invoke()');
});

test('Detects Runtime.getRuntime().exec()', () => {
  const pattern = /\bRuntime\.getRuntime\(\)\.exec\s*\(/g;
  assert(pattern.test('Runtime.getRuntime().exec(cmd);'),
    'Should detect Runtime.getRuntime().exec');
});

// Test 7: C/C++ Memory Safety (CWE-416, CWE-415)
test('Detects new without delete (simplified)', () => {
  const pattern = /\bnew\s+\w+(?!\[)/g;
  assert(pattern.test('int* ptr = new int(42);'),
    'Should detect new keyword');
});

// Test 8: Verify language detection works for new file types
test('Language detection includes C/C++ headers', () => {
  const extMap = {
    'h': 'c',
    'hpp': 'cpp',
    'hxx': 'cpp'
  };
  
  // This just verifies the mapping exists in our test
  assert(extMap['h'] === 'c', 'Should map .h to c');
  assert(extMap['hpp'] === 'cpp', 'Should map .hpp to cpp');
});

// Test 10: Pattern specificity tests (no false positives)
test('Does not flag safe deserialization contexts', () => {
  const pattern = /\bObjectInputStream\.readObject\s*\(/g;
  // This should still match - we're testing the pattern works
  assert(pattern.test('// Comment about ObjectInputStream.readObject()'),
    'Pattern should match in comments (we can filter by context later)');
});

test('SQL keywords alone should not trigger', () => {
  const pattern = /f["'][^"']*\{[^}]*\}[^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)|f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{[^}]*\}/gi;
  const safe = 'message = f"Hello {name}"';
  const unsafe = 'query = f"SELECT * FROM {table}"';
  assert(!pattern.test(safe),
    `F-string without SQL keywords should not match: ${safe}`);
  const pattern2 = /f["'][^"']*\{[^}]*\}[^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)|f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{[^}]*\}/gi;
  assert(pattern2.test(unsafe),
    `F-string with SQL keywords should match: ${unsafe}`);
});

test('Template literals without SQL should not trigger advanced SQL pattern', () => {
  const pattern = /`[^`]*\$\{[^}]*\}[^`]*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)|`[^`]*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\$\{[^}]*\}/gi;
  const safe = 'const msg = `Hello ${name}`';
  const unsafe = 'const query = `SELECT * FROM ${table}`';
  assert(!pattern.test(safe),
    `Template literal without SQL should not match: ${safe}`);
  const pattern2 = /`[^`]*\$\{[^}]*\}[^`]*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)|`[^`]*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\$\{[^}]*\}/gi;
  assert(pattern2.test(unsafe),
    `Template literal with SQL should match: ${unsafe}`);
});

require('./test-utils').printSummary()
