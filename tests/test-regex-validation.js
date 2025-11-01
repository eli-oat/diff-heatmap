#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const { test, assert } = require('./test-utils')

const scriptPath = path.join(__dirname, '..', 'diff-heatmap.js')
const scriptContent = fs.readFileSync(scriptPath, 'utf-8')
eval(scriptContent.match(/const RULES = \{[\s\S]*?\n\};/)[0])

function shouldMatch(pattern, text, description) {
  pattern.lastIndex = 0; // Reset regex state
  if (!pattern.test(text)) {
    throw new Error(`Should match "${text}" - ${description}`);
  }
}

function shouldNotMatch(pattern, text, description) {
  pattern.lastIndex = 0; // Reset regex state
  if (pattern.test(text)) {
    throw new Error(`Should NOT match "${text}" - ${description}`);
  }
}

console.log('=== Regex Pattern Validation Tests ===\n');

// Test secrets patterns
console.log('--- Secrets Patterns ---');
test('Long alphanumeric strings', () => {
  const p = /(['"][a-zA-Z0-9]{32,}['"])/g;
  shouldMatch(p, '"sk1234567890abcdefghijklmnopqrstuvwxyz"', 'API key');
  shouldMatch(p, "'aaaabbbbccccddddeeeeffffgggghhhh'", '32+ chars');
  shouldNotMatch(p, '"shortkey"', 'too short');
  shouldNotMatch(p, 'noQuotes1234567890abcdefghijklmnopqrstuvwxyz', 'no quotes');
});

test('Credential assignments', () => {
  const p = /\b(api[_-]?key|secret|password|token|auth)\s*[:=]\s*['"][^'"]+['"]/gi;
  shouldMatch(p, 'api_key = "12345"', 'api_key with underscore');
  shouldMatch(p, 'apiKey: "test"', 'apiKey camelCase');
  shouldMatch(p, 'password = "secret"', 'password');
  shouldMatch(p, 'token: "abc123"', 'token');
  shouldNotMatch(p, 'apikey', 'no assignment');
});

test('GitHub tokens', () => {
  const p = /\b(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}\b/g;
  shouldMatch(p, 'ghp_1234567890abcdefghijklmnopqrstuvwxyz', 'GitHub personal token');
  shouldMatch(p, 'gho_abcdefghijklmnopqrstuvwxyz1234567890', 'GitHub OAuth token');
  shouldNotMatch(p, 'ghp_short', 'too short');
  shouldNotMatch(p, 'token_1234567890abcdefghijklmnopqrstuvwxyz', 'wrong prefix');
});

test('AWS access keys', () => {
  const p = /\b(AKIA[0-9A-Z]{16})\b/g;
  shouldMatch(p, 'AKIAIOSFODNN7EXAMPLE', 'AWS access key');
  shouldMatch(p, 'AKIA1234567890ABCDEF', '20 chars total');
  shouldNotMatch(p, 'AKIA123', 'too short');
  shouldNotMatch(p, 'AKIAabcdefghijklmnop', 'lowercase not allowed');
});

// Test dangerous functions
console.log('\n--- Dangerous Functions ---');
test('eval/exec patterns', () => {
  const p = /\b(eval|exec|execFile|spawn)\s*\(/g;
  shouldMatch(p, 'eval(code)', 'eval');
  shouldMatch(p, 'exec(command)', 'exec');
  shouldMatch(p, 'spawn(cmd)', 'spawn');
  shouldNotMatch(p, 'evaluate(x)', 'evaluate is different');
  shouldNotMatch(p, 'execute()', 'execute is different');
});

test('DOM injection patterns', () => {
  const p = /\b(innerHTML|outerHTML|document\.write|execScript)\b/g;
  shouldMatch(p, 'element.innerHTML = content', 'innerHTML');
  shouldMatch(p, 'div.outerHTML = html', 'outerHTML');
  shouldMatch(p, 'document.write("<div>")', 'document.write');
  shouldNotMatch(p, 'innerText = value', 'innerText is safe');
});

// Test SQL injection patterns
console.log('\n--- SQL Injection ---');
test('SQL keywords in strings', () => {
  const p = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+/gi;
  shouldMatch(p, 'SELECT * FROM users', 'SELECT');
  shouldMatch(p, 'INSERT INTO table', 'INSERT');
  shouldMatch(p, 'DROP TABLE users', 'DROP');
  shouldNotMatch(p, 'selecting items', 'not SQL keyword');
});

test('Python f-string SQL injection', () => {
  const p = /f["'][^"']*\{[^}]*\}[^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)|f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{[^}]*\}/gi;
  shouldMatch(p, 'f"SELECT * FROM {table}"', 'f-string with SELECT');
  shouldMatch(p, 'f"{user_id} WHERE id"', 'f-string with WHERE after');
  shouldNotMatch(p, 'f"Hello {name}"', 'no SQL keywords');
  shouldNotMatch(p, '"SELECT * FROM users"', 'not an f-string');
});

test('String format SQL injection', () => {
  const p = /["'].*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\.format\(/gi;
  shouldMatch(p, '"SELECT * FROM {}".format(table)', 'format with SELECT');
  shouldNotMatch(p, '"Hello {}".format(name)', 'no SQL keywords');
});

// Test buffer overflow patterns
console.log('\n--- Buffer Overflow (C/C++) ---');
test('Unsafe C string functions', () => {
  const p = /\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|sscanf|fscanf)\s*\(/g;
  shouldMatch(p, 'strcpy(dest, src)', 'strcpy');
  shouldMatch(p, 'gets(buffer)', 'gets');
  shouldMatch(p, 'sprintf(buf, "%s", str)', 'sprintf');
  shouldNotMatch(p, 'strncpy(dest, src, n)', 'strncpy is different');
});

test('Bounded string functions', () => {
  const p = /(strncpy|strncat|snprintf|vsnprintf)\s*\(/g;
  shouldMatch(p, 'strncpy(dest, src, 100)', 'strncpy');
  shouldMatch(p, 'snprintf(buf, 100, "%s", str)', 'snprintf');
  shouldNotMatch(p, 'strcpy(dest, src)', 'strcpy is unbounded');
});

// Test deserialization
console.log('\n--- Deserialization ---');
test('Java readObject', () => {
  const p = /readObject\s*\(/g;
  shouldMatch(p, 'ois.readObject()', 'readObject call');
  shouldMatch(p, 'ObjectInputStream.readObject()', 'with class name');
  shouldNotMatch(p, 'readObjectFromFile()', 'different method');
});

test('Python pickle', () => {
  const p = /(pickle\.loads?|pickle\.Unpickler|yaml\.load|marshal\.loads?)\s*\(/g;
  shouldMatch(p, 'pickle.loads(data)', 'pickle.loads');
  shouldMatch(p, 'pickle.load(file)', 'pickle.load');
  shouldMatch(p, 'yaml.load(content)', 'yaml.load');
  shouldNotMatch(p, 'pickle.dump(obj, file)', 'dump is serialization, not deserialization');
});

// Test PHP superglobals
console.log('\n--- PHP Input Injection ---');
test('PHP superglobals', () => {
  const p = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/g;
  shouldMatch(p, '$_GET["id"]', '$_GET');
  shouldMatch(p, '$_POST["data"]', '$_POST');
  shouldMatch(p, '$_REQUEST["param"]', '$_REQUEST');
  shouldNotMatch(p, '$_SERVER["HTTP_HOST"]', '$_SERVER is different');
});

test('PHP file inclusion', () => {
  const p = /\binclude\s*\(\s*\$_(GET|POST|REQUEST)/g;
  shouldMatch(p, 'include($_GET["page"])', 'include with $_GET');
  shouldMatch(p, 'include( $_POST["file"])', 'with spaces');
  shouldNotMatch(p, 'include("header.php")', 'static include');
});

// Test mutable state patterns
console.log('\n--- Mutable State ---');
test('Global let/var', () => {
  const p = /^(let|var)\s+\w+\s*=/gm;
  shouldMatch(p, 'let globalCounter = 0', 'global let');
  shouldMatch(p, 'var state = {}', 'global var');
  shouldNotMatch(p, 'const CONSTANT = 42', 'const is immutable');
  shouldNotMatch(p, '  let localVar = 1', 'indented (not global)');
});

test('Python global mutable dict', () => {
  const p = /^[A-Z_]+\s*=\s*\{/gm;
  shouldMatch(p, 'CACHE = {}', 'global dict');
  shouldMatch(p, 'CONFIG = {"key": "value"}', 'dict with content');
  shouldNotMatch(p, 'cache = {}', 'lowercase (not constant convention)');
  shouldNotMatch(p, '  CACHE = {}', 'indented');
});

test('Java AtomicInteger', () => {
  const p = /\bAtomicInteger|AtomicLong|AtomicBoolean|AtomicReference/g;
  shouldMatch(p, 'AtomicInteger counter', 'AtomicInteger');
  shouldMatch(p, 'private AtomicLong total', 'AtomicLong');
  shouldNotMatch(p, 'AtomInteger x', 'typo');
});

test('Instance field mutation (this)', () => {
  const p = /this\.\w+\s*=(?!=)/g;
  shouldMatch(p, 'this.count = 0', 'this.count assignment');
  shouldMatch(p, 'this.state = newValue', 'this.state assignment');
  shouldNotMatch(p, 'if (this.count === 0)', 'comparison, not assignment');
  shouldNotMatch(p, 'this.count == 0', 'loose comparison');
});

test('Array mutation methods', () => {
  const p = /\.push\(|\.pop\(|\.shift\(|\.unshift\(|\.splice\(/g;
  shouldMatch(p, 'arr.push(item)', 'push');
  shouldMatch(p, 'arr.pop()', 'pop');
  shouldMatch(p, 'list.splice(0, 1)', 'splice');
  shouldNotMatch(p, 'arr.map(x => x)', 'map is immutable');
});

test('Compound assignment', () => {
  const p = /\b(\w+)\s*[+\-*/]=\s*/g;
  shouldMatch(p, 'count += 1', '+=');
  shouldMatch(p, 'total *= 2', '*=');
  shouldNotMatch(p, 'if (x = 5)', 'single = is assignment');
});

// Test HTML/XSS patterns
console.log('\n--- HTML/XSS Vectors ---');
test('Script tags', () => {
  const p = /<script[^>]*>.*<\/script>/gi;
  shouldMatch(p, '<script>alert(1)</script>', 'basic script tag');
  shouldMatch(p, '<script src="evil.js"></script>', 'script with src');
  shouldNotMatch(p, '<div>script</div>', 'just the word script');
});

test('Inline event handlers', () => {
  const p = /on(click|load|error|mouseover|focus|blur|change|submit)\s*=/gi;
  shouldMatch(p, 'onclick="alert(1)"', 'onclick');
  shouldMatch(p, 'onload = "run()"', 'onload with spaces');
  shouldMatch(p, 'onerror="hack()"', 'onerror');
  shouldNotMatch(p, 'on="value"', 'just "on"');
});

test('javascript: protocol', () => {
  const p = /javascript:/gi;
  shouldMatch(p, 'href="javascript:alert(1)"', 'javascript: in href');
  shouldMatch(p, 'JAVASCRIPT:void(0)', 'case insensitive');
  shouldNotMatch(p, '// javascript comment', 'in comment');
});

test('React dangerouslySetInnerHTML', () => {
  const p = /dangerouslySetInnerHTML/g;
  shouldMatch(p, 'dangerouslySetInnerHTML={{__html: content}}', 'React prop');
  shouldNotMatch(p, 'innerHTML = value', 'plain innerHTML');
});

// Test ReDoS patterns
console.log('\n--- ReDoS (Regular Expression DoS) ---');
test('Nested quantifiers', () => {
  const p = /\/.*\(\.\*\+.*\)\+.*\//g;
  shouldMatch(p, '/(.*+)+/', 'nested + quantifiers');
  shouldNotMatch(p, '/(.*)+/', 'single quantifier');
});

test('Dynamic regex construction', () => {
  const p = /new RegExp\([^)]*\+/g;
  shouldMatch(p, 'new RegExp("pattern" + userInput)', 'regex with concat');
  shouldNotMatch(p, 'new RegExp("^static$")', 'static regex');
});

// Test config security
console.log('\n--- Configuration Security ---');
test('Debug mode enabled', () => {
  const p = /debug\s*[:=]\s*true/gi;
  shouldMatch(p, 'debug: true', 'debug true');
  shouldMatch(p, 'DEBUG = True', 'uppercase');
  shouldNotMatch(p, 'debug: false', 'debug false is safe');
});

test('CORS allow all', () => {
  const p = /cors.*origin.*\*/gi;
  shouldMatch(p, 'cors: { origin: "*" }', 'CORS wildcard');
  shouldNotMatch(p, 'cors: { origin: "https://example.com" }', 'specific origin');
});

// Test prototype pollution
console.log('\n--- Prototype Pollution ---');
test('__proto__ access', () => {
  const p = /\[['"]__proto__['"]\]/g;
  shouldMatch(p, 'obj["__proto__"]', 'bracket notation');
  shouldMatch(p, "obj['__proto__']", 'single quotes');
  shouldNotMatch(p, 'obj.prototype', 'regular prototype');
});

test('constructor.prototype access', () => {
  const p = /\[['"]constructor['"]\]\[['"]prototype['"]\]/g;
  shouldMatch(p, 'obj["constructor"]["prototype"]', 'constructor.prototype');
  shouldNotMatch(p, 'obj.constructor', 'just constructor');
});

// Test resource leaks
console.log('\n--- Resource Leaks ---');
test('setInterval without cleanup', () => {
  const p = /setInterval\(/g;
  shouldMatch(p, 'setInterval(fn, 1000)', 'setInterval call');
  shouldNotMatch(p, 'setTimeout(fn, 1000)', 'setTimeout is one-time');
});

test('addEventListener without cleanup', () => {
  const p = /addEventListener\(/g;
  shouldMatch(p, 'element.addEventListener("click", handler)', 'addEventListener');
  shouldNotMatch(p, 'removeEventListener("click", handler)', 'cleanup');
});

// Test timing attacks
console.log('\n--- Timing Attacks ---');
test('Direct password comparison', () => {
  const p = /===.*password|password.*===/gi;
  shouldMatch(p, 'if (input === password)', 'password comparison');
  shouldMatch(p, 'password === userInput', 'reverse order');
  shouldNotMatch(p, 'if (password.length > 0)', 'property access');
});

// Test file operations
console.log('\n--- File Operations ---');
test('chmod 777', () => {
  const p = /chmod\s+777/g;
  shouldMatch(p, 'chmod 777 file.txt', 'chmod 777');
  shouldNotMatch(p, 'chmod 755 file.txt', 'chmod 755 is safer');
});

test('Hardcoded temp path', () => {
  const p = /\/tmp\/[a-zA-Z0-9_-]+/g;
  shouldMatch(p, '/tmp/myfile', 'hardcoded temp');
  shouldMatch(p, 'path = "/tmp/cache-123"', 'temp with numbers');
  shouldNotMatch(p, 'tempfile.mkdtemp()', 'secure temp creation');
});

// Test SSRF patterns
console.log('\n--- SSRF (Server-Side Request Forgery) ---');
test('fetch with user input', () => {
  const p = /fetch\([^)]*req\.(query|body|params)/gi;
  shouldMatch(p, 'fetch(req.query.url)', 'fetch with req.query');
  shouldMatch(p, 'fetch(req.body.endpoint)', 'fetch with req.body');
  shouldNotMatch(p, 'fetch("https://api.example.com")', 'static URL');
});

// Test XXE patterns
console.log('\n--- XXE (XML External Entity) ---');
test('XML entity declaration', () => {
  const p = /<!ENTITY/gi;
  shouldMatch(p, '<!ENTITY xxe SYSTEM "file:///etc/passwd">', 'entity declaration');
  shouldNotMatch(p, '<!-- comment -->', 'HTML comment');
});

test('Python XML parsing', () => {
  const p = /(?<!defusedxml\.)etree\.(parse|fromstring)/g;
  shouldMatch(p, 'etree.parse(xml_file)', 'etree.parse');
  shouldMatch(p, 'tree = etree.fromstring(xml_string)', 'etree.fromstring');
  shouldNotMatch(p, 'defusedxml.etree.parse(xml)', 'defusedxml is safe');
});

require('./test-utils').printSummary()
