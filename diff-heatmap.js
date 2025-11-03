#!/usr/bin/env node

// === Color Codes ===

const ANSI = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  gray: '\x1b[90m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  black: '\x1b[30m',
  // Highlight colors (bright/bold variants for inline emphasis)
  brightRed: '\x1b[91m',
  brightYellow: '\x1b[93m',
  brightWhite: '\x1b[97m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgWhite: '\x1b[47m',
  bold: '\x1b[1m',
  underline: '\x1b[4m'
}

// === Functional Utilities ===

const pipe = (...fns) => (x) => fns.reduce((acc, fn) => fn(acc), x)

// === ADTs ===

/**
 * @typedef {{tag: 'Header', text: string}} HeaderLine
 * @typedef {{tag: 'Context', text: string}} ContextLine
 * @typedef {{tag: 'Removed', text: string}} RemovedLine
 * @typedef {{tag: 'Added', text: string, score: number, language: string}} AddedLine
 * @typedef {HeaderLine | ContextLine | RemovedLine | AddedLine} DiffLine
 */

const DiffLine = {
  Header: (text) => ({ tag: 'Header', text }),
  Context: (text) => ({ tag: 'Context', text }),
  Removed: (text) => ({ tag: 'Removed', text }),
  Added: (text, score, reasons = [], language = 'unknown') => ({ tag: 'Added', text, score, reasons, language })
}

/**
 * @typedef {{
 *   text: string,
 *   context: {prev: string[], next: string[], indent: number}
 * }} LineContext
 */

// === Pattern Definitions ===
// This is trying to be a centralized pattern store for all highlighting rules


// === Configurable Rules ===

const RULES = {
  // === CRITICAL SECURITY (0.90-0.95) ===
  // Highest severity issues - deserialization, memory corruption, XXE
  
  deserialization: {
    score: 0.95,
    highlightClass: 'secret',
    patterns: [
      { regex: /readObject\s*\(/g, desc: 'Java unsafe deserialization', languages: ['java'] },
      { regex: /XMLDecoder/g, desc: 'Java XML deserialization', languages: ['java'] },
      { regex: /XStream\s*\(/g, desc: 'XStream deserialization', languages: ['java'] },
      { regex: /(pickle\.loads?|pickle\.Unpickler|yaml\.load|marshal\.loads?)\s*\(/g, desc: 'Python unsafe deserialization', languages: ['python'] },
      { regex: /unserialize\s*\(/g, desc: 'PHP unsafe deserialization', languages: ['php'] },
      { regex: /JSON\.parse\([^)]*untrusted/gi, desc: 'Untrusted JSON parse', languages: ['javascript', 'typescript'] }
    ]
  },
  
  buffer_overflow: {
    score: 0.95,
    highlightClass: 'secret',
    patterns: [
      { regex: /\b(strcpy|strcat|gets|sprintf|vsprintf|scanf|sscanf|fscanf)\s*\(/g, desc: 'Unsafe C string functions', languages: ['c', 'cpp'] },
      { regex: /\b(strncpy|strncat|snprintf|vsnprintf)\s*\(/g, desc: 'Potentially unsafe bounded string functions', languages: ['c', 'cpp'] },
      { regex: /\bmemcpy\s*\([^,)]+,\s*[^,)]+,\s*[^)]*sizeof[^)]*\*[^)]*\)/g, desc: 'memcpy with calculated size (overflow risk)', languages: ['c', 'cpp'] },
      { regex: /\balloca\s*\(/g, desc: 'Stack allocation (overflow risk)', languages: ['c', 'cpp'] }
    ]
  },
  
  memory_safety: {
    score: 0.90,
    highlightClass: 'secret',
    patterns: [
      { regex: /\bfree\s*\([^)]+\);[^{]*\1/g, desc: 'Potential double free', languages: ['c', 'cpp'] },
      { regex: /\bdelete\s+[^;]+;[^{]*\1/g, desc: 'Potential double delete', languages: ['cpp'] },
      { regex: /\*\w+\s*=[^;]*;\s*free\s*\(\w+\)/g, desc: 'Use after free pattern', languages: ['c', 'cpp'] },
      { regex: /\bnew\s+\w+(?!\[)(?!.*delete)/g, desc: 'new without matching delete', languages: ['cpp'] }
    ]
  },
  
  xxe_patterns: {
    score: 0.90,
    highlightClass: 'secret',
    patterns: [
      { regex: /<!ENTITY/gi, desc: 'XML entity declaration (XXE risk)', languages: ['xml', 'html'] },
      { regex: /DocumentBuilderFactory(?!.*setFeature.*FEATURE_SECURE_PROCESSING)/g, desc: 'XML parser without secure processing', languages: ['java'] },
      { regex: /SAXParserFactory(?!.*setFeature)/g, desc: 'SAX parser without feature restriction', languages: ['java'] },
      { regex: /(?<!defusedxml\.)etree\.(parse|fromstring)/g, desc: 'Python XML parsing (check for defusedxml)', languages: ['python'] },
      { regex: /libxml_disable_entity_loader\(false\)/g, desc: 'PHP XML entity loader enabled', languages: ['php'] }
    ]
  },
  
  secrets: {
    score: 0.9,
    highlightClass: 'secret',
    patterns: [
      { regex: /(['"][a-zA-Z0-9]{32,}['"])/g, desc: 'Long alphanumeric strings' },
      { regex: /\b(api[_-]?key|secret|password|token|auth)\s*[:=]\s*['"][^'"]+['"]/gi, desc: 'Credential assignments' },
      { regex: /\b(sk-[a-zA-Z0-9]{32,}|pk-[a-zA-Z0-9]{32,})\b/g, desc: 'API keys (OpenAI, Stripe, etc)' },
      { regex: /\b([0-9a-f]{40,64})\b/g, desc: 'Hex keys (SHA hashes, tokens)' },
      { regex: /-----BEGIN (PRIVATE|RSA|OPENSSH) KEY-----/g, desc: 'Private keys' },
      { regex: /\b(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}\b/g, desc: 'GitHub tokens' },
      { regex: /\b(AKIA[0-9A-Z]{16})\b/g, desc: 'AWS access keys' }
    ]
  },
  
  // === HIGH SECURITY - INJECTIONS (0.80-0.85) ===
  // Injection attacks, XSS, command execution, dangerous operations
  
  dangerous_functions: {
    score: 0.85,
    highlightClass: 'danger',
    patterns: [
      { regex: /\b(eval|exec|execFile|spawn)\s*\(/g, desc: 'Code execution', languages: ['javascript', 'typescript', 'python', 'ruby'] },
      { regex: /\b(innerHTML|outerHTML|document\.write|execScript)\b/g, desc: 'DOM injection', languages: ['javascript', 'typescript'] },
      { regex: /\b(system|shell_exec|passthru|proc_open)\s*\(/g, desc: 'Shell execution', languages: ['php'] },
      { regex: /\b(__import__|compile|globals|locals)\s*\(/g, desc: 'Dynamic imports', languages: ['python'] },
      { regex: /\b(eval|instance_eval|class_eval|module_eval)\b/g, desc: 'Dynamic evaluation', languages: ['ruby'] },
      { regex: /\b(Runtime\.getRuntime|ProcessBuilder)\b/g, desc: 'Process execution', languages: ['java'] },
      { regex: /\bsystem\s*\(/g, desc: 'System calls', languages: ['c', 'cpp', 'rust'] }
    ]
  },
  
  sql_injection_advanced: {
    score: 0.85,
    highlightClass: 'danger',
    patterns: [
      { regex: /f["'][^"']*\{[^}]*\}[^"']*(SELECT\s+(\*|COUNT|MAX|MIN|AVG|SUM|\w+)\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE)|f["'][^"']*(SELECT\s+(\*|COUNT|MAX|MIN|AVG|SUM|\w+)\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE)[^"']*\{[^}]*\}/gi, desc: 'Python f-string SQL injection', languages: ['python'] },
      { regex: /["'].*(SELECT\s+(\*|COUNT|MAX|MIN|AVG|SUM|\w+)\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE).*\.format\(/gi, desc: 'String format SQL injection', languages: ['python', 'csharp'] },
      { regex: /`[^`]*\$\{[^}]*\}[^`]*(SELECT\s+(\*|COUNT|MAX|MIN|AVG|SUM|\w+)\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE)|`[^`]*(SELECT\s+(\*|COUNT|MAX|MIN|AVG|SUM|\w+)\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|WHERE)[^`]*\$\{[^}]*\}/gi, desc: 'Template literal SQL injection', languages: ['javascript', 'typescript'] },
      { regex: /execute\s*\(\s*["'][^"']*\%s[^"']*["']\s*\%/g, desc: 'Python string formatting in SQL execute', languages: ['python'] },
      { regex: /query\s*\(\s*["'][^"']*\+/g, desc: 'String concatenation in query', languages: ['javascript', 'typescript', 'java', 'csharp', 'php'] }
    ]
  },
  
  input_injection: {
    score: 0.85,
    highlightClass: 'danger',
    patterns: [
      { regex: /\$_(GET|POST|REQUEST|COOKIE)\s*\[/g, desc: 'PHP superglobal usage (validate input)', languages: ['php'] },
      { regex: /\binclude\s*\(\s*\$_(GET|POST|REQUEST)/g, desc: 'PHP file inclusion with user input', languages: ['php'] },
      { regex: /\brequire\s*\(\s*\$_(GET|POST|REQUEST)/g, desc: 'PHP file require with user input', languages: ['php'] },
      { regex: /\bexec\s*\([^)]*\$_(GET|POST|REQUEST)/g, desc: 'PHP exec with user input', languages: ['php'] },
      { regex: /\bshell_exec\s*\([^)]*\$_(GET|POST|REQUEST)/g, desc: 'PHP shell_exec with user input', languages: ['php'] }
    ]
  },
  
  html_xss_vectors: {
    score: 0.85,
    highlightClass: 'danger',
    patterns: [
      { regex: /<script[^>]*>.*<\/script>/gi, desc: 'Script tags in content', languages: ['html', 'javascript', 'typescript', 'php'] },
      { regex: /on(click|load|error|mouseover|focus|blur|change|submit)\s*=/gi, desc: 'Inline event handlers', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<iframe[^>]*src=/gi, desc: 'iframe with dynamic src', languages: ['html', 'javascript', 'typescript', 'php'] },
      { regex: /<(object|embed|applet)[^>]*>/gi, desc: 'Embedded objects', languages: ['html'] },
      { regex: /javascript:/gi, desc: 'javascript: protocol', languages: ['html', 'javascript', 'typescript'] },
      { regex: /data:text\/html/gi, desc: 'data URI with HTML', languages: ['html', 'javascript', 'typescript'] },
      { regex: /\.srcdoc\s*=/g, desc: 'iframe srcdoc attribute', languages: ['javascript', 'typescript'] },
      { regex: /dangerouslySetInnerHTML/g, desc: 'React dangerouslySetInnerHTML', languages: ['javascript', 'typescript'] },
      { regex: /v-html=/g, desc: 'Vue v-html directive', languages: ['javascript', 'typescript'] },
      { regex: /\[innerHTML\]=/g, desc: 'Angular innerHTML binding', languages: ['typescript'] }
    ]
  },
  
  prototype_pollution: {
    score: 0.85,
    highlightClass: 'danger',
    patterns: [
      { regex: /\[['"]__proto__['"]\]/g, desc: '__proto__ property access', languages: ['javascript', 'typescript'] },
      { regex: /\[['"]constructor['"]\]\[['"]prototype['"]\]/g, desc: 'constructor.prototype access', languages: ['javascript', 'typescript'] },
      { regex: /Object\.prototype\.\w+\s*=/g, desc: 'Modifying Object.prototype', languages: ['javascript', 'typescript'] },
      { regex: /\.\s*__proto__\s*=/g, desc: 'Direct __proto__ assignment', languages: ['javascript', 'typescript'] }
    ]
  },
  
  sql_injection: {
    score: 0.8,
    highlightClass: 'warning',
    patterns: [
      { regex: /\bSELECT\s+(\*|COUNT|MAX|MIN|AVG|SUM|\w+|\w+\.\w+|DISTINCT|TOP\s+\d+)\s+FROM\s+/gi, desc: 'SQL query structure' },
      { regex: /\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE)/gi, desc: 'SQL query structure' },
      { regex: /['"].*\+.*WHERE/gi, desc: 'String concatenation with WHERE' },
      { regex: /['"].*\$\{.*\}.*WHERE/g, desc: 'Template literals with WHERE', languages: ['javascript', 'typescript'] },
      { regex: /f['"].*WHERE/g, desc: 'F-strings with WHERE', languages: ['python'] }
    ]
  },
  
  path_traversal: {
    score: 0.8,
    highlightClass: 'danger',
    patterns: [
      { regex: /\.\.[\/ \\]/g, desc: 'Directory traversal' },
      { regex: /\b(readFileSync|readFile|open)\s*\([^,)]*\+/g, desc: 'File read with concatenation', languages: ['javascript', 'typescript', 'python'] }
    ]
  },
  
  java_reflection: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      { regex: /Class\.forName\s*\(/g, desc: 'Dynamic class loading', languages: ['java'] },
      { regex: /\.invoke\s*\(/g, desc: 'Reflection method invocation', languages: ['java'] },
      { regex: /Constructor\.newInstance\s*\(/g, desc: 'Reflection constructor invocation', languages: ['java'] },
      { regex: /Runtime\.getRuntime\(\)\.exec\s*\(/g, desc: 'Runtime command execution', languages: ['java'] }
    ]
  },
  
  regex_dos: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      { regex: /\/.*\(\.\*\+.*\)\+.*\//g, desc: 'Nested quantifiers (ReDoS risk)', languages: ['javascript', 'typescript', 'python', 'ruby', 'php'] },
      { regex: /\/.*\(\.\*\*.*\)\*.*\//g, desc: 'Exponential backtracking pattern', languages: ['javascript', 'typescript', 'python', 'ruby'] },
      { regex: /\/\(\.\*\)\+\+/g, desc: 'Possessive quantifier misuse', languages: ['javascript', 'typescript'] },
      { regex: /new RegExp\([^)]*\+/g, desc: 'Dynamic regex construction', languages: ['javascript', 'typescript'] },
      { regex: /re\.compile\([^)]*\+/g, desc: 'Dynamic regex compilation', languages: ['python'] }
    ]
  },
  
  config_security: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      { regex: /debug\s*[:=]\s*true/gi, desc: 'Debug mode enabled', languages: ['javascript', 'typescript', 'python', 'ruby', 'yaml', 'json'] },
      { regex: /DEBUG\s*=\s*True/g, desc: 'Django DEBUG = True', languages: ['python'] },
      { regex: /NODE_ENV.*development/gi, desc: 'Development mode in production', languages: ['javascript', 'typescript'] },
      { regex: /cors.*origin.*\*/gi, desc: 'CORS allow all origins', languages: ['javascript', 'typescript', 'python', 'java'] },
      { regex: /verify\s*[:=]\s*false/gi, desc: 'SSL verification disabled', languages: ['python', 'javascript', 'typescript'] },
      { regex: /strictSSL\s*:\s*false/g, desc: 'Strict SSL disabled', languages: ['javascript', 'typescript'] },
      { regex: /AllowOverride\s+All/g, desc: 'Apache AllowOverride All', languages: ['apache'] }
    ]
  },
  
  ssrf_patterns: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      { regex: /fetch\([^)]*req\.(query|body|params)/gi, desc: 'fetch with user-controlled URL', languages: ['javascript', 'typescript'] },
      { regex: /axios\.(get|post)\([^)]*req\./gi, desc: 'axios with user input', languages: ['javascript', 'typescript'] },
      { regex: /requests\.(get|post)\([^)]*request\./gi, desc: 'Python requests with user input', languages: ['python'] },
      { regex: /urllib\.request\.urlopen\([^)]*input/gi, desc: 'urllib with user input', languages: ['python'] },
      { regex: /http\.Get\([^)]*r\./g, desc: 'Go HTTP GET with request data', languages: ['go'] }
    ]
  },
  
  ldap_injection: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      { regex: /ldap\.search\([^)]*\+/g, desc: 'LDAP search with concatenation', languages: ['python', 'java'] },
      { regex: /InitialDirContext.*search\([^)]*\+/g, desc: 'Java LDAP search with concat', languages: ['java'] },
      { regex: /LdapConnection.*Search\([^)]*\+/g, desc: 'C# LDAP search with concat', languages: ['csharp'] }
    ]
  },
  
  insecure_random_security: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      { regex: /Math\.random\(\).*token|token.*Math\.random\(\)/gi, desc: 'Math.random for token generation', languages: ['javascript', 'typescript'] },
      { regex: /Math\.random\(\).*session|session.*Math\.random\(\)/gi, desc: 'Math.random for session IDs', languages: ['javascript', 'typescript'] },
      { regex: /random\.randint.*password|password.*random\.randint/gi, desc: 'random.randint for passwords', languages: ['python'] },
      { regex: /new Random\(\).*token|token.*new Random\(\)/gi, desc: 'java.util.Random for tokens', languages: ['java'] }
    ]
  },
  
  // === MEDIUM SECURITY (0.75-0.80) ===
  // Crypto, timing attacks, file operations, shared state
  
  weak_crypto: {
    score: 0.75,
    highlightClass: 'warning',
    patterns: [
      { regex: /\b(md5|sha1|des|rc4)\b/gi, desc: 'Weak hash algorithms' },
      { regex: /Math\.random\(\)/g, desc: 'Insecure random', languages: ['javascript', 'typescript'] },
      { regex: /\brandom\(\)/g, desc: 'Insecure random', languages: ['php', 'python'] },
      { regex: /\bnew\s+Random\(\)/g, desc: 'Insecure random', languages: ['java', 'csharp'] }
    ]
  },
  
  markdown_injection: {
    score: 0.75,
    highlightClass: 'warning',
    patterns: [
      { regex: /\[.*\]\(javascript:/gi, desc: 'Markdown link with javascript:', languages: ['markdown'] },
      { regex: /\[.*\]\(data:/gi, desc: 'Markdown link with data URI', languages: ['markdown'] },
      { regex: /!\[.*\]\(.*onerror=/gi, desc: 'Markdown image with onerror', languages: ['markdown'] },
      { regex: /<script/gi, desc: 'Script tag in markdown', languages: ['markdown'] },
      { regex: /^#{1,6}\s+<script/gm, desc: 'Script in markdown heading', languages: ['markdown'] },
      { regex: /\]\]\(/g, desc: 'Markdown link injection pattern', languages: ['markdown'] }
    ]
  },
  
  timing_attacks: {
    score: 0.75,
    highlightClass: 'warning',
    patterns: [
      { regex: /===.*password|password.*===/gi, desc: 'Direct password comparison (timing attack)', languages: ['javascript', 'typescript', 'python'] },
      { regex: /===.*token|token.*===/gi, desc: 'Direct token comparison (timing attack)', languages: ['javascript', 'typescript', 'python'] },
      { regex: /===.*secret|secret.*===/gi, desc: 'Direct secret comparison (timing attack)', languages: ['javascript', 'typescript', 'python'] },
      { regex: /\.equals\(.*password|password.*\.equals/gi, desc: 'String password comparison', languages: ['java'] },
      { regex: /strcmp.*password|password.*strcmp/gi, desc: 'C string comparison on secrets', languages: ['c', 'cpp'] }
    ]
  },
  
  file_operations: {
    score: 0.75,
    highlightClass: 'warning',
    patterns: [
      { regex: /chmod\s+777/g, desc: 'Overly permissive file permissions', languages: ['shell', 'python'] },
      { regex: /os\.chmod\([^,]+,\s*0o777/g, desc: 'Python chmod 777', languages: ['python'] },
      { regex: /mkdtemp\(\)/g, desc: 'Temp directory without cleanup', languages: ['python'] },
      { regex: /tempfile\(\)/g, desc: 'Temp file creation (check cleanup)', languages: ['python', 'php'] },
      { regex: /File\.createTempFile/g, desc: 'Temp file creation (Java)', languages: ['java'] },
      { regex: /\/tmp\/[a-zA-Z0-9_-]+/g, desc: 'Hardcoded temp path (race condition risk)', languages: ['shell', 'python', 'ruby'] }
    ]
  },
  
  rust_specific: {
    score: 0.75,
    highlightClass: 'warning',
    languages: ['rust'],
    patterns: [
      { regex: /\.unwrap\(\)/g, desc: 'Unwrap without error handling' },
      { regex: /\.expect\(/g, desc: 'Expect without proper error handling' },
      { regex: /\bunsafe\s*\{/g, desc: 'Unsafe block' }
    ]
  },
  
  shared_mutable_state: {
    score: 0.75,
    highlightClass: 'warning',
    patterns: [
      { regex: /\bVolatile<\w+>/g, desc: 'Volatile shared state (Java)', languages: ['java'] },
      { regex: /\bvolatile\s+\w+/g, desc: 'Volatile keyword (C/C++/C#)', languages: ['c', 'cpp', 'csharp'] },
      { regex: /\bAtomicInteger|AtomicLong|AtomicBoolean|AtomicReference/g, desc: 'Atomic types (Java concurrency)', languages: ['java'] },
      { regex: /threading\.Lock|threading\.RLock|threading\.Semaphore/g, desc: 'Thread synchronization primitives (Python)', languages: ['python'] },
      { regex: /sync\.Mutex|sync\.RWMutex/g, desc: 'Mutex usage (Go)', languages: ['go'] },
      { regex: /std::mutex|std::shared_mutex|std::lock_guard/g, desc: 'Mutex usage (C++)', languages: ['cpp'] },
      { regex: /Mutex::new|RwLock::new|Arc::new/g, desc: 'Shared mutable state (Rust)', languages: ['rust'] },
      { regex: /lock\s*\(/g, desc: 'Lock acquisition (various)', languages: ['java', 'csharp', 'python'] }
    ]
  },
  
  // === LANGUAGE-SPECIFIC (0.70-0.75) ===
  // Per-language antipatterns and code quality issues
  
  javascript_specific: {
    score: 0.7,
    highlightClass: 'warning',
    languages: ['javascript', 'typescript'],
    patterns: [
      { regex: /\b(with|arguments\.callee)\b/g, desc: 'Deprecated features' },
      { regex: /(?<![!=])==(?![=>])/g, desc: 'Loose equality (use === instead)' },
      { regex: /(?<![!=])!=(?!=)/g, desc: 'Loose inequality (use !== instead)' },
      { regex: /\b(var)\s+/g, desc: 'var keyword' }
    ]
  },
  
  python_specific: {
    score: 0.7,
    highlightClass: 'warning',
    languages: ['python'],
    patterns: [
      { regex: /\bexcept:\s*$/gm, desc: 'Bare except clause' },
      { regex: /\bpickle\.loads?\(/g, desc: 'Unsafe deserialization' },
      { regex: /\bassert\s+/g, desc: 'Assert in production code' }
    ]
  },
  
  go_specific: {
    score: 0.7,
    highlightClass: 'warning',
    languages: ['go'],
    patterns: [
      { regex: /\bpanic\(/g, desc: 'Panic calls' },
      { regex: /:=.*err\s*[^=]/g, desc: 'Potential unchecked error' }
    ]
  },
  
  global_mutable_state: {
    score: 0.70,
    highlightClass: 'warning',
    patterns: [
      { regex: /^(let|var)\s+\w+\s*=/gm, desc: 'Global mutable variable (JS)', languages: ['javascript', 'typescript'] },
      { regex: /^[A-Z_]+\s*=\s*\{/gm, desc: 'Global mutable dict/list (Python)', languages: ['python'] },
      { regex: /^[A-Z_]+\s*=\s*\[/gm, desc: 'Global mutable list (Python)', languages: ['python'] },
      { regex: /^var\s+\w+\s*=/gm, desc: 'Package-level var (Go)', languages: ['go'] },
      { regex: /static\s+mut\s+/g, desc: 'Static mutable (Rust)', languages: ['rust'] },
      { regex: /public\s+static\s+(?!final)\w+/g, desc: 'Public static non-final field (Java)', languages: ['java'] },
      { regex: /public\s+static\s+(?!readonly)\w+/g, desc: 'Public static non-readonly field (C#)', languages: ['csharp'] }
    ]
  },
  
  closure_mutable_state: {
    score: 0.70,
    highlightClass: 'warning',
    patterns: [
      { regex: /let\s+\w+\s*=.*=>\s*{[^}]*\1\s*=(?!=)/g, desc: 'Closure mutating outer scope (JS)', languages: ['javascript', 'typescript'] },
      { regex: /var\s+\w+\s*=.*func\([^)]*\)\s*{[^}]*\1\s*=(?!=)/g, desc: 'Closure mutating outer scope (Go)', languages: ['go'] },
      { regex: /\bnonlocal\s+\w+/g, desc: 'Nonlocal mutable state (Python)', languages: ['python'] }
    ]
  },
  
  // === CODE QUALITY - STATE MANAGEMENT (0.55-0.70) ===
  // Mutable state patterns, generally safe but worth reviewing
  
  mutable_class_state: {
    score: 0.65,
    highlightClass: 'warning',
    patterns: [
      { regex: /this\.\w+\s*=(?!=)/g, desc: 'Instance field mutation', languages: ['javascript', 'typescript', 'java', 'csharp', 'python'] },
      { regex: /self\.\w+\s*=(?!=)/g, desc: 'Self field mutation', languages: ['python', 'rust'] },
      { regex: /\bsetState\s*\(/g, desc: 'React setState (mutable state)', languages: ['javascript', 'typescript'] },
      { regex: /\bprivate\s+(?!final|readonly)\w+\s+\w+;/g, desc: 'Private mutable field', languages: ['java', 'csharp'] },
      { regex: /\bprotected\s+(?!final|readonly)\w+\s+\w+;/g, desc: 'Protected mutable field', languages: ['java', 'csharp'] }
    ]
  },
  
  collection_mutation: {
    score: 0.60,
    highlightClass: 'complex',
    patterns: [
      { regex: /\.push\(|\.pop\(|\.shift\(|\.unshift\(|\.splice\(/g, desc: 'Array mutation methods (JS)', languages: ['javascript', 'typescript'] },
      { regex: /\.append\(|\.extend\(|\.remove\(|\.pop\(|\.insert\(/g, desc: 'List mutation methods (Python)', languages: ['python'] },
      { regex: /\.add\(|\.remove\(|\.clear\(|\.put\(/g, desc: 'Collection mutation (Java)', languages: ['java'] },
      { regex: /\.Add\(|\.Remove\(|\.Clear\(/g, desc: 'Collection mutation (C#)', languages: ['csharp'] },
      { regex: /\[\w+\]\s*=(?!=)/g, desc: 'Array/Map element mutation', languages: ['javascript', 'typescript', 'python', 'go', 'rust'] }
    ]
  },
  
  reassignment_patterns: {
    score: 0.55,
    highlightClass: 'complex',
    patterns: [
      { regex: /\b(\w+)\s*=\s*\1\s*[+\-*/]/g, desc: 'Self-modifying reassignment (x = x + 1)', languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'go'] },
      { regex: /\b(\w+)\s*[+\-*/]=\s*/g, desc: 'Compound assignment (+=, -=, etc)', languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'c', 'cpp', 'go'] },
      { regex: /\+\+\w+|\w+\+\+|--\w+|\w+--/g, desc: 'Increment/decrement operators', languages: ['javascript', 'typescript', 'java', 'csharp', 'c', 'cpp', 'go'] }
    ]
  },
  
  // === CODE QUALITY - GENERAL (0.50-0.65) ===
  // General code quality, complexity, resource management
  
  resource_leaks: {
    score: 0.65,
    highlightClass: 'warning',
    patterns: [
      { regex: /new\s+(File|Socket|Stream)\w+\(/g, desc: 'Resource allocation without try-with-resources', languages: ['java'] },
      { regex: /open\([^)]+\)(?!.*with)/g, desc: 'Python file open without context manager', languages: ['python'] },
      { regex: /setInterval\(/g, desc: 'setInterval (check for clearInterval)', languages: ['javascript', 'typescript'] },
      { regex: /addEventListener\(/g, desc: 'Event listener (check for cleanup)', languages: ['javascript', 'typescript'] },
      { regex: /subscribe\(/g, desc: 'Subscription (check for unsubscribe)', languages: ['javascript', 'typescript'] }
    ]
  },
  
  complex_conditionals: {
    score: 0.6,
    highlightClass: 'complex',
    patterns: [
      { regex: /([&|]{2,})/g, desc: 'Multiple logical operators' },
      { regex: /\bif\s*\([^)]{80,}\)/g, desc: 'Very long if conditions' }
    ]
  },
  
  network_operations: {
    score: 0.50,
    highlightClass: 'complex',
    patterns: [
      { regex: /\b(fetch|XMLHttpRequest|axios)\s*\(/g, desc: 'Network/HTTP calls', languages: ['javascript', 'typescript'] },
      { regex: /\b(requests\.(get|post|put|delete)|urllib\.request)\b/g, desc: 'HTTP requests', languages: ['python'] },
      { regex: /\bhttp\.(Get|Post|Client)/g, desc: 'HTTP client usage', languages: ['go'] },
      { regex: /\b(localStorage|sessionStorage)\.setItem/g, desc: 'Browser storage writes', languages: ['javascript', 'typescript'] }
    ]
  },
  
  // === ACCESSIBILITY (0.65-0.80) ===
  // WCAG violations, ARIA misuse, keyboard/focus issues
  
  accessibility_critical: {
    score: 0.80,
    highlightClass: 'danger',
    patterns: [
      // CSS outline removal without alternative
      { regex: /outline\s*:\s*(0|none)/gi, desc: 'Outline removed (keyboard focus indicator)', languages: ['css', 'javascript', 'typescript'] },
      { regex: /outline-width\s*:\s*0/gi, desc: 'Outline width zero (keyboard focus)', languages: ['css', 'javascript', 'typescript'] },
      // Missing alt text patterns
      { regex: /<img(?![^>]*alt=)/gi, desc: 'img without alt attribute', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<img[^>]*alt\s*=\s*['"]\s*['"]/gi, desc: 'img with empty alt text (verify intentional)', languages: ['html', 'javascript', 'typescript'] },
      // Interactive elements without labels (removed input pattern - too many false positives with <label for="id">)
      // Button with only icon content (no visible text)
      { regex: /<button(?![^>]*aria-label)(?![^>]*aria-labelledby)[^>]*>\s*<(svg|i)[^>]*>\s*<\/(svg|i)>\s*<\/button>/gi, desc: 'button with only icon (verify accessible label)', languages: ['html', 'javascript', 'typescript'] },
      // Auto-playing media
      { regex: /<(video|audio)[^>]*autoplay/gi, desc: 'Auto-playing media (accessibility issue)', languages: ['html', 'javascript', 'typescript'] },
      // Positive tabindex (tab order manipulation)
      { regex: /tabindex\s*=\s*['"]?[1-9]\d*/gi, desc: 'Positive tabindex (breaks natural tab order)', languages: ['html', 'javascript', 'typescript'] },
      // Color-only information
      { regex: /color\s*[:=]\s*['"]?(red|green)['"]?\s*;?\s*(\/\/|\/\*).*(error|success|warning)/gi, desc: 'Color-only status indicator', languages: ['css', 'javascript', 'typescript'] }
    ]
  },
  
  accessibility_aria_issues: {
    score: 0.75,
    highlightClass: 'warning',
    patterns: [
      // ARIA misuse patterns
      { regex: /role\s*=\s*['"]presentation['"][^>]*aria-/gi, desc: 'ARIA attributes on presentation role', languages: ['html', 'javascript', 'typescript'] },
      { regex: /role\s*=\s*['"]none['"][^>]*aria-/gi, desc: 'ARIA attributes on none role', languages: ['html', 'javascript', 'typescript'] },
      // Redundant ARIA roles
      { regex: /<button[^>]*role\s*=\s*['"]button['"]/gi, desc: 'Redundant role on button', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<nav[^>]*role\s*=\s*['"]navigation['"]/gi, desc: 'Redundant role on nav', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<main[^>]*role\s*=\s*['"]main['"]/gi, desc: 'Redundant role on main', languages: ['html', 'javascript', 'typescript'] },
      // ARIA without proper relationships (removed - unreliable in line-by-line processing)
      // Invalid ARIA on non-interactive elements
      { regex: /<div[^>]*aria-expanded/gi, desc: 'aria-expanded on div (needs role or interactive element)', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<span[^>]*aria-checked/gi, desc: 'aria-checked on span (needs role or interactive element)', languages: ['html', 'javascript', 'typescript'] },
      // ARIA required children/parents
      { regex: /role\s*=\s*['"]listitem['"](?![^<]*<[^>]*(ul|ol|role\s*=\s*['"]list))/gi, desc: 'listitem role without list parent', languages: ['html', 'javascript', 'typescript'] },
      { regex: /role\s*=\s*['"]option['"](?![^<]*role\s*=\s*['"]listbox)/gi, desc: 'option role without listbox parent', languages: ['html', 'javascript', 'typescript'] },
      { regex: /role\s*=\s*['"]tab['"](?![^<]*role\s*=\s*['"]tablist)/gi, desc: 'tab role without tablist parent', languages: ['html', 'javascript', 'typescript'] }
    ]
  },
  
  accessibility_keyboard_issues: {
    score: 0.60,
    highlightClass: 'warning',
    patterns: [
      // onClick without keyboard support
      { regex: /onClick\s*=(?![^}]*onKeyDown|[^}]*onKeyPress|[^}]*onKeyUp)/gi, desc: 'onClick without keyboard handler', languages: ['javascript', 'typescript'] },
      { regex: /<div[^>]*onclick(?![^>]*onkeydown|[^>]*onkeypress|[^>]*tabindex)/gi, desc: 'onclick on div without keyboard support', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<span[^>]*onclick(?![^>]*onkeydown|[^>]*onkeypress|[^>]*tabindex)/gi, desc: 'onclick on span without keyboard support', languages: ['html', 'javascript', 'typescript'] },
      // Tabindex without role
      { regex: /tabindex\s*=\s*['"]0['"](?![^>]*role\s*=)/gi, desc: 'tabindex=0 without role (verify element purpose)', languages: ['html', 'javascript', 'typescript'] },
      { regex: /tabindex\s*=\s*['"]?-1['"]?(?![^>]*role\s*=)/gi, desc: 'tabindex=-1 without role (verify focus management)', languages: ['html', 'javascript', 'typescript'] },
      // Focus management issues
      { regex: /\.focus\(\)(?![^;]*\.blur\(\))/g, desc: 'focus() call without blur management', languages: ['javascript', 'typescript'] },
      { regex: /autoFocus/g, desc: 'autoFocus (verify use in modals/dialogs)', languages: ['javascript', 'typescript'] },
      // Mouse-only events
      { regex: /onmouseover(?![^>]*onfocus)/gi, desc: 'mouseover without focus equivalent', languages: ['html', 'javascript', 'typescript'] },
      { regex: /onmouseout(?![^>]*onblur)/gi, desc: 'mouseout without blur equivalent', languages: ['html', 'javascript', 'typescript'] }
    ]
  },
  
  accessibility_semantic_html: {
    score: 0.60,
    highlightClass: 'warning',
    patterns: [
      // Semantic HTML violations
      { regex: /<div[^>]*role\s*=\s*['"]button['"]/gi, desc: 'div as button (use <button> instead)', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<div[^>]*role\s*=\s*['"]link['"]/gi, desc: 'div as link (use <a> instead)', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<span[^>]*role\s*=\s*['"]heading['"]/gi, desc: 'span as heading (use <h1>-<h6> instead)', languages: ['html', 'javascript', 'typescript'] },
      // Heading level skipping
      { regex: /<h1[^>]*>.*<\/h1>\s*<h3/gi, desc: 'Skipped heading level (h1 to h3)', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<h2[^>]*>.*<\/h2>\s*<h4/gi, desc: 'Skipped heading level (h2 to h4)', languages: ['html', 'javascript', 'typescript'] },
      // Form accessibility
      { regex: /<form(?![^>]*role\s*=\s*['"]search['"])(?![^>]*aria-label)/gi, desc: 'form without accessible name (consider adding)', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<select(?![^>]*aria-label)(?![^>]*id\s*=)/gi, desc: 'select without label', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<textarea(?![^>]*aria-label)(?![^>]*id\s*=)/gi, desc: 'textarea without label', languages: ['html', 'javascript', 'typescript'] },
      // Table accessibility
      { regex: /<table(?![^>]*<caption)(?![^>]*aria-label)(?![^>]*role\s*=\s*['"]presentation)/gi, desc: 'table without caption or aria-label', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<th(?![^>]*scope\s*=)/gi, desc: 'th without scope attribute', languages: ['html', 'javascript', 'typescript'] },
      // Link accessibility
      { regex: /<a[^>]*href\s*=\s*['"][^'"]*['"](?![^>]*>(?!\s*<))>/gi, desc: 'link with no text content', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<a[^>]*>(?:click here|here|read more|link)\s*<\/a>/gi, desc: 'Non-descriptive link text', languages: ['html', 'javascript', 'typescript'] }
    ]
  },
  
  accessibility_content_issues: {
    score: 0.65,
    highlightClass: 'warning',
    patterns: [
      // Language specification
      { regex: /<html(?![^>]*lang\s*=)/gi, desc: 'html without lang attribute', languages: ['html'] },
      // Title requirements
      { regex: /<iframe(?![^>]*title\s*=)/gi, desc: 'iframe without title', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<svg(?![^>]*role\s*=|[^>]*aria-label)/gi, desc: 'svg without role or aria-label', languages: ['html', 'javascript', 'typescript'] },
      // Text alternatives
      { regex: /<canvas(?![^>]*aria-label)>/gi, desc: 'canvas without fallback content', languages: ['html', 'javascript', 'typescript'] },
      { regex: /<object(?![^>]*aria-label)(?![^>]*<\/object>)/gi, desc: 'object without fallback', languages: ['html', 'javascript', 'typescript'] },
      // Time limits
      { regex: /setTimeout\([^,)]*redirect|window\.location\s*=.*setTimeout/gi, desc: 'Timed redirect (provide user control)', languages: ['javascript', 'typescript'] },
      // Text sizing and zoom
      { regex: /user-scalable\s*=\s*['"]?no['"]?/gi, desc: 'Viewport zoom disabled', languages: ['html', 'javascript', 'typescript'] },
      { regex: /maximum-scale\s*=\s*['"]?1['"]?/gi, desc: 'Maximum scale prevents zoom', languages: ['html', 'javascript', 'typescript'] },
      // Required fields
      { regex: /<input[^>]*required(?![^>]*aria-required)/gi, desc: 'required without aria-required', languages: ['html', 'javascript', 'typescript'] },
      // Error handling
      { regex: /aria-invalid\s*=\s*['"]true['"](?![^>]*aria-describedby)/gi, desc: 'aria-invalid without error description', languages: ['html', 'javascript', 'typescript'] }
    ]
  }
};

const PATTERNS = {
  secrets: RULES.secrets.patterns.map(p => p.regex),
  danger: [...RULES.dangerous_functions.patterns.map(p => p.regex), 
           ...RULES.path_traversal.patterns.map(p => p.regex)],
  warning: [...RULES.weak_crypto.patterns.map(p => p.regex), 
            ...RULES.sql_injection.patterns.map(p => p.regex)],
  complexity: RULES.complex_conditionals.patterns.map(p => p.regex)
};

// === Rule System Helpers ===

/**
 * Detect file language from filename
 */
function detectLanguage(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const extensionMap = {
    // Programming languages
    'js': 'javascript',
    'jsx': 'javascript',
    'ts': 'typescript',
    'tsx': 'typescript',
    'py': 'python',
    'rb': 'ruby',
    'php': 'php',
    'java': 'java',
    'go': 'go',
    'rs': 'rust',
    'c': 'c',
    'h': 'c',
    'cpp': 'cpp',
    'cc': 'cpp',
    'cxx': 'cpp',
    'hpp': 'cpp',
    'hxx': 'cpp',
    'cs': 'csharp',
    'sh': 'shell',
    'bash': 'shell',
    // Web languages
    'html': 'html',
    'htm': 'html',
    'css': 'css',
    'scss': 'css',
    'sass': 'css',
    'less': 'css',
    'vue': 'javascript',
    'svelte': 'javascript',
    'xml': 'xml',
    'json': 'json',
    'yaml': 'yaml',
    'yml': 'yaml',
    // Documentation and text files
    'md': 'markdown',
    'markdown': 'markdown',
    'txt': 'text',
    'text': 'text',
    'rst': 'text',
    'adoc': 'text',
    'asciidoc': 'text'
  };
  return extensionMap[ext] || 'unknown';
}

/**
 * Check if a rule applies to a given language
 */
function ruleAppliesTo(rule, language) {
  // Documentation and text files - only apply security rules that make sense in any context
  // NOTE: 'unknown' means we couldn't detect the language - treat as code to be safe
  const isDocumentation = ['markdown', 'text'].includes(language);
  
  if (isDocumentation) {
    // Only apply rules that are universally applicable (secrets, credentials)
    // Skip code-specific patterns (SQL, XSS, code quality, etc.)
    const docSafeRules = ['secrets', 'deserialization', 'buffer_overflow', 'memory_safety'];
    const ruleName = Object.keys(RULES).find(key => RULES[key] === rule);
    
    if (!docSafeRules.includes(ruleName)) {
      return false; // Skip this rule for documentation files
    }
  }
  
  if (!rule.languages) return true; // Rule applies to all languages
  if (language === 'unknown') return true; // Apply all rules if language unknown (safer)
  return rule.languages.includes(language);
}

function patternAppliesTo(pattern, language) {
  if (!pattern.languages) return true; // Pattern applies to all languages
  if (language === 'unknown') return true; // Apply all patterns if language unknown
  return pattern.languages.includes(language);
}

/**
 * Check if a pattern matches text
 */
const patternMatches = (pattern, text) => {
  pattern.regex.lastIndex = 0 // Reset regex state for global patterns
  return pattern.regex.test(text)
}

/**
 * Get score from a rule if any pattern matches
 * Returns: {score: number, reasons: string[]}
 * Collects ALL matching patterns from the rule
 */
const scoreFromRule = (rule, text, language) => {
  if (!ruleAppliesTo(rule, language)) return { score: 0, reasons: [] }
  
  const matchingPatterns = rule.patterns.filter(pattern =>
    patternAppliesTo(pattern, language) && patternMatches(pattern, text)
  )
  
  return matchingPatterns.length > 0
    ? { score: rule.score, reasons: matchingPatterns.map(p => p.desc) }
    : { score: 0, reasons: [] }
}

/**
 * Score text against all rules
 * Returns: {score: number, reasons: string[]}
 * Stacks scores with diminishing returns (first match full, additional +50%)
 */
const scoreWithRules = (text, language = 'unknown') => {
  const results = Object.values(RULES)
    .map(rule => scoreFromRule(rule, text, language))
    .filter(r => r.score > 0)
    .sort((a, b) => b.score - a.score) // Highest score first
  
  if (results.length === 0) {
    return { score: 0, reasons: [] }
  }
  
  // First match gets full score, additional matches add 50% of their value
  const stackedScore = results.reduce((total, result, index) => {
    const multiplier = index === 0 ? 1.0 : 0.5
    return total + (result.score * multiplier)
  }, 0)
  
  // Cap at 1.0
  const score = Math.min(1.0, stackedScore)
  const allReasons = results.flatMap(r => r.reasons)
  
  return { score, reasons: allReasons }
}



const classifyLine = (line) => {
  if (line.startsWith('diff ') || line.startsWith('index ') || 
      line.startsWith('--- ') || line.startsWith('+++ ') ||
      line.startsWith('@@')) {
    return DiffLine.Header(line)
  }
  if (line.startsWith('+')) {
    return DiffLine.Added(line.slice(1), 0, [], 'unknown')
  }
  if (line.startsWith('-')) {
    return DiffLine.Removed(line.slice(1))
  }
  return DiffLine.Context(line)
}

/**
 * Parse git diff output into structured lines
 * Pre: input is valid git diff format
 * Post: each line is tagged with its type
 */
const parseDiff = (input) => input.split('\n').map(classifyLine)

/**
 * Build context for each line
 * Pre: diffLines is ordered array
 * Post: returns context with prev/next lines, indentation, and change statistics
 */
function buildContext(diffLines, index) {
  const windowSize = 3
  const largeWindowSize = 10
  const prev = []
  const next = []
  
  for (let i = Math.max(0, index - windowSize); i < index; i++) {
    const line = diffLines[i]
    if (line.tag === 'Added' || line.tag === 'Context') {
      prev.push(line.text)
    }
  }
  
  for (let i = index + 1; i < Math.min(diffLines.length, index + windowSize + 1); i++) {
    const line = diffLines[i]
    if (line.tag === 'Added' || line.tag === 'Context') {
      next.push(line.text)
    }
  }
  
  const currentText = diffLines[index].tag === 'Added' ? diffLines[index].text : ''
  const indent = currentText.match(/^\s*/)[0].length
  
  // Calculate change statistics in larger window
  let totalChangesNearby = 0
  let totalLinesNearby = 0
  let consecutiveAdded = 0
  let consecutiveRemoved = 0
  
  // Count consecutive additions before current line
  for (let i = index - 1; i >= 0; i--) {
    if (diffLines[i].tag === 'Added') {
      consecutiveAdded++
    } else if (diffLines[i].tag !== 'Removed') {
      break
    }
  }
  
  // Count consecutive additions after current line (if current is Added)
  if (diffLines[index].tag === 'Added') {
    consecutiveAdded++ // Include current line
    for (let i = index + 1; i < diffLines.length; i++) {
      if (diffLines[i].tag === 'Added') {
        consecutiveAdded++
      } else if (diffLines[i].tag !== 'Removed') {
        break
      }
    }
  }
  
  // Count total changes and removals in larger window
  const startIdx = Math.max(0, index - largeWindowSize)
  const endIdx = Math.min(diffLines.length, index + largeWindowSize + 1)
  
  for (let i = startIdx; i < endIdx; i++) {
    totalLinesNearby++
    if (diffLines[i].tag === 'Added' || diffLines[i].tag === 'Removed') {
      totalChangesNearby++
    }
    if (diffLines[i].tag === 'Removed') {
      consecutiveRemoved++
    }
  }
  
  const changeRatio = totalLinesNearby > 0 ? totalChangesNearby / totalLinesNearby : 0
  
  return { 
    prev, 
    next, 
    indent,
    totalChangesNearby,
    consecutiveAdded,
    consecutiveRemoved,
    changeRatio
  }
}

/**
 * Score complexity based on operators and nesting
 * Returns: {score: number, reasons: string[]}
 */
const scoreComplexity = (text, context) => {
  const operators = (text.match(/[&|!<>=]/g) || []).length
  const controlCount = (text.match(/\b(if|for|while|switch|catch)\b/g) || []).length
  
  const operatorScore = operators > 5 ? 0.8 : operators > 3 ? 0.6 : 0
  const controlScore = controlCount > 0 ? 0.4 : 0
  const indentScore = context.indent > 20 ? 0.7 : context.indent > 12 ? 0.5 : 0
  const lengthScore = text.length > 150 ? 0.6 : text.length > 100 ? 0.4 : 0
  
  const reasons = []
  if (operatorScore > 0) reasons.push(`Complex expression (${operators} operators)`)
  if (controlScore > 0) reasons.push('Contains control flow')
  if (indentScore > 0) reasons.push(`Deep nesting (${context.indent} spaces)`)
  if (lengthScore > 0) reasons.push(`Long line (${text.length} chars)`)
  
  return { 
    score: Math.max(operatorScore, controlScore, indentScore, lengthScore),
    reasons
  }
}

/**
 * Score based on change context
 * Isolated changes = higher attention needed
 * Returns: {score: number, reasons: string[]}
 */
const scoreChangeType = (context) => {
  const isIsolated = (context.prev.length + context.next.length) === 0
  return {
    score: isIsolated ? 0.3 : 0,
    reasons: isIsolated ? ['Isolated change'] : []
  }
}

/**
 * Score based on magnitude of changes
 * Large consecutive blocks and high change density = bulk rewrite/refactor
 * Returns: {score: number, reasons: string[]}
 */
const scoreLargeChanges = (context) => {
  const reasons = []
  let score = 0
  
  // Consecutive additions (likely a large new block or function rewrite)
  if (context.consecutiveAdded >= 15) {
    score = Math.max(score, 0.6)
    reasons.push(`Large addition (${context.consecutiveAdded} consecutive lines)`)
  } else if (context.consecutiveAdded >= 8) {
    score = Math.max(score, 0.5)
    reasons.push(`Bulk addition (${context.consecutiveAdded} consecutive lines)`)
  } else if (context.consecutiveAdded >= 5) {
    score = Math.max(score, 0.4)
    reasons.push(`Multi-line addition (${context.consecutiveAdded} lines)`)
  }
  
  // High change density (likely refactoring or rewrite)
  if (context.changeRatio >= 0.7 && context.totalChangesNearby >= 8) {
    score = Math.max(score, 0.5)
    reasons.push(`High change density (${Math.round(context.changeRatio * 100)}% of nearby lines)`)
  } else if (context.changeRatio >= 0.5 && context.totalChangesNearby >= 6) {
    score = Math.max(score, 0.4)
    reasons.push(`Moderate change density (${Math.round(context.changeRatio * 100)}%)`)
  }
  
  // Function rewrite pattern (many removes + many adds nearby)
  if (context.consecutiveRemoved >= 5 && context.consecutiveAdded >= 5) {
    score = Math.max(score, 0.55)
    reasons.push('Potential function rewrite')
  }
  
  return { score, reasons }
}

/**
 * Score a single line for attention priority
 * Pre: line is text string, context is object with prev/next/indent/changeStats
 * Post: returns {score: number, reasons: string[]}
 * Stacks scores with diminishing returns (first match full, additional +50%)
 */
const scoreLine = (line, context, language = 'unknown') => {
  const ruleResult = scoreWithRules(line, language)
  const complexityResult = scoreComplexity(line, context)
  const changeTypeResult = scoreChangeType(context)
  const largeChangeResult = scoreLargeChanges(context)
  
  // Collect all score sources and sort by highest first
  const sources = [ruleResult, complexityResult, changeTypeResult, largeChangeResult]
    .filter(s => s.score > 0)
    .sort((a, b) => b.score - a.score)
  
  if (sources.length === 0) {
    return { score: 0, reasons: [] }
  }
  
  // First source gets full score, additional sources add 50% of their value
  const stackedScore = sources.reduce((total, source, index) => {
    const multiplier = index === 0 ? 1.0 : 0.5
    return total + (source.score * multiplier)
  }, 0)
  
  // Cap at 1.0
  const score = Math.min(1.0, stackedScore)
  const reasons = sources.flatMap(s => s.reasons)
  
  return { score, reasons }
}

/**
 * Map score to color
 * Post: deterministic mapping [0,1] > ANSI color
 */
function scoreToColor(score) {
  if (score >= 0.7) return ANSI.red
  if (score >= 0.4) return ANSI.yellow
  if (score >= 0.2) return ANSI.green
  return ANSI.reset
}


// Map pattern types to ANSI colors
const ANSI_COLOR_MAP = {
  secrets: ANSI.bgWhite + ANSI.black + ANSI.bold,
  danger: ANSI.brightWhite + ANSI.underline + ANSI.bold,
  warning: ANSI.brightYellow + ANSI.underline,
  complexity: ANSI.bold
};

// Create ANSI patterns from shared pattern definitions
const ANSI_PATTERNS = Object.entries(PATTERNS).flatMap(([type, regexes]) =>
  regexes.map(regex => ({ regex, color: ANSI_COLOR_MAP[type] }))
);

/**
 * Apply all ANSI highlights to text
 * Skips highlighting for documentation files (markdown, text)
 */
const applyInlineHighlights = (text, lineColor, language = 'unknown') => {
  // Skip inline highlights for documentation and text files
  const isDocumentation = ['markdown', 'text'].includes(language);
  if (isDocumentation) {
    return text;
  }
  
  return ANSI_PATTERNS.reduce((result, { regex, color }) =>
    result.replace(regex, `${color}$1${ANSI.reset}${lineColor}`),
    text
  );
};

/**
 * Apply scores to all Added lines
 * Pre: diffLines is parsed
 * Post: all Added lines have valid scores
 * 
 * Extract filename from diff headers
 */
const extractFilename = (diffLines) => {
  const fileHeader = diffLines.find(line => 
    line.tag === 'Header' && line.text.startsWith('+++')
  )
  
  if (!fileHeader) return null
  
  // Extract from "+++ b/path/to/file.ext"
  const match = fileHeader.text.match(/\+\+\+\s+[ab]\/(.+)/)
  return match ? match[1] : null
}

/**
 * Score all lines in diff with language detection
 * extractFilename > detectLanguage > map(scoreLine)
 */
const scoreAllLines = (diffLines) => {
  const filename = extractFilename(diffLines)
  const language = filename ? detectLanguage(filename) : 'unknown'
  
  return diffLines.map((line, index) => {
    if (line.tag === 'Added') {
      const result = scoreLine(line.text, buildContext(diffLines, index), language)
      return DiffLine.Added(line.text, result.score, result.reasons, language)
    }
    return line
  })
}

/**
 * Colorize diff line based on type and score
 * Post: returns ANSI colored string with inline highlights
 */
const colorizeLine = (line) => {
  const colorizers = {
    Header: (l) => `${ANSI.cyan}${l.text}${ANSI.reset}`,
    Context: (l) => `${ANSI.gray}${l.text}${ANSI.reset}`,
    Removed: (l) => `${ANSI.red}-${l.text}${ANSI.reset}`,
    Added: (l) => {
      const color = scoreToColor(l.score)
      const highlighted = applyInlineHighlights(l.text, color, l.language)
      return `${color}+${highlighted}${ANSI.reset}`
    }
  }
  
  return colorizers[line.tag](line)
}

/**
 * Render all lines to string
 * Post: preserves line ordering and structure
 */
const renderDiff = (diffLines) => diffLines.map(colorizeLine).join('\n')



// === Main Pipeline ===

const processDiff = pipe(
  parseDiff,
  scoreAllLines,
  renderDiff
)



// === HTML Output ===

const escapeHtml = (text) => 
  text.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));

// Map pattern types to HTML class names
const CLASS_MAP = {
  secrets: 'hl-secret',
  danger: 'hl-danger',
  warning: 'hl-warning',
  complexity: 'hl-complex'
};

// Create HTML patterns from shared pattern definitions
const HTML_PATTERNS = Object.entries(PATTERNS).flatMap(([type, regexes]) =>
  regexes.map(regex => ({ regex, className: CLASS_MAP[type] }))
);

// Compose all highlights in a pipeline
// Skips highlighting for documentation files (markdown, text)
const applyInlineHighlightsHTML = (text, language = 'unknown') => {
  // Skip inline highlights for documentation and text files
  const isDocumentation = ['markdown', 'text'].includes(language);
  if (isDocumentation) {
    return escapeHtml(text);
  }
  
  return HTML_PATTERNS.reduce((result, { regex, className }) =>
    result.replace(regex, `<span class="${className}">$1</span>`),
    escapeHtml(text)
  );
};

// Score to CSS class mapping (pure function) - legacy
const scoreToClassHTML = (score) =>
  score >= 0.7 ? 'added-high' :
  score >= 0.4 ? 'added-medium' :
  score >= 0.2 ? 'added-low' :
  'added-normal';

// Convert score to heatmap color (smooth gradient)
function scoreToHeatmapColor(score) {
  // Heatmap gradient: green > yellow > orange > red
  // 0.0-0.2: green (#4ec9b0) - safe
  // 0.2-0.5: yellow (#d7ba7d) - medium
  // 0.5-0.8: orange (#ff8800) - concerning
  // 0.8-1.0: red (#f48771) - dangerous
  
  let color, alpha;
  
  if (score < 0.2) {
    // Green to light green (0.0 - 0.2)
    const t = score / 0.2;
    color = interpolateColor([78, 201, 176], [106, 220, 200], t);
    alpha = 0.10 + t * 0.05; // 0.10 to 0.15
  } else if (score < 0.5) {
    // Light green to yellow (0.2 - 0.5)
    const t = (score - 0.2) / 0.3;
    color = interpolateColor([106, 220, 200], [215, 186, 125], t);
    alpha = 0.15 + t * 0.05; // 0.15 to 0.20
  } else if (score < 0.8) {
    // Yellow to orange (0.5 - 0.8)
    const t = (score - 0.5) / 0.3;
    color = interpolateColor([215, 186, 125], [255, 136, 0], t);
    alpha = 0.20 + t * 0.10; // 0.20 to 0.30
  } else {
    // Orange to red (0.8 - 1.0)
    const t = (score - 0.8) / 0.2;
    color = interpolateColor([255, 136, 0], [244, 135, 113], t);
    alpha = 0.30 + t * 0.20; // 0.30 to 0.50
  }
  
  return color.replace('rgb', 'rgba').replace(')', `, ${alpha})`);
}

// Interpolate between two RGB colors
function interpolateColor(color1, color2, t) {
  const r = Math.round(color1[0] + (color2[0] - color1[0]) * t);
  const g = Math.round(color1[1] + (color2[1] - color1[1]) * t);
  const b = Math.round(color1[2] + (color2[2] - color1[2]) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

// Get text color based on background brightness
function getTextColor(bgColor) {
  // Extract RGB values from rgb(r, g, b)
  const match = bgColor.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
  if (!match) return '#d4d4d4';
  
  const [, r, g, b] = match.map(Number);
  // Calculate brightness using relative luminance
  const brightness = (r * 299 + g * 587 + b * 114) / 1000;
  
  // Dark text for light backgrounds, light text for dark backgrounds
  return brightness > 128 ? '#1e1e1e' : '#d4d4d4';
}

function renderDiffHTML(diffLines) {
  let html = '<div class="container">';
  let lineNum = 1;
  let inTable = false;
  
  for (const line of diffLines) {
    switch (line.tag) {
      case 'Header':
        if (line.text.startsWith('diff --git')) {
          if (inTable) {
            html += '</tbody></table>';
            inTable = false;
          }
          html += `<div class="file-header">${escapeHtml(line.text)}</div>`;
          html += '<table class="diff-table unified"><tbody>';
          inTable = true;
        } else if (line.text.startsWith('@@')) {
          html += `<tr><td colspan="2" class="hunk-header">${escapeHtml(line.text)}</td></tr>`;
          // Extract starting line number from hunk header
          const match = line.text.match(/@@ -\d+,?\d* \+(\d+),?\d* @@/);
          if (match) lineNum = parseInt(match[1]);
        } else if (inTable) {
          html += `<tr><td colspan="2" class="header">${escapeHtml(line.text)}</td></tr>`;
        }
        break;
      case 'Context':
        if (!inTable) {
          html += '<table class="diff-table unified"><tbody>';
          inTable = true;
        }
        html += `<tr><td class="line-num">${lineNum}</td><td class="line-content context">${escapeHtml(line.text)}</td></tr>`;
        lineNum++;
        break;
      case 'Removed':
        if (!inTable) {
          html += '<table class="diff-table unified"><tbody>';
          inTable = true;
        }
        html += `<tr><td class="line-num"></td><td class="line-content removed">-${escapeHtml(line.text)}</td></tr>`;
        break;
      case 'Added':
        if (!inTable) {
          html += '<table class="diff-table unified"><tbody>';
          inTable = true;
        }
        const bgColor = scoreToHeatmapColor(line.score);
        const textColor = getTextColor(bgColor);
        const highlighted = applyInlineHighlightsHTML(line.text, line.language);
        const titleAttr = line.reasons && line.reasons.length > 0 
          ? ` title="${escapeHtml(line.reasons.join('; '))}"` 
          : '';
        html += `<tr><td class="line-num">${lineNum}</td><td class="line-content added"${titleAttr} style="background-color: ${bgColor}; color: ${textColor};">+${highlighted}</td></tr>`;
        lineNum++;
        break;
      default:
        if (inTable) {
          html += `<tr><td class="line-num"></td><td class="line-content">${escapeHtml(line.text)}</td></tr>`;
        }
        break;
    }
  }
  
  if (inTable) {
    html += '</tbody></table>';
  }
  html += '</div>';
  
  return html;
}

// === Side-by-Side Diff Parser ===

function parseSideBySide(input) {
  const lines = input.split('\n');
  const files = [];
  let currentFile = null;
  let leftLine = 0;
  let rightLine = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (line.startsWith('diff --git')) {
      if (currentFile) files.push(currentFile);
      currentFile = {
        header: line,
        oldFile: '',
        newFile: '',
        hunks: []
      };
    } else if (line.startsWith('---')) {
      if (currentFile) currentFile.oldFile = line;
    } else if (line.startsWith('+++')) {
      if (currentFile) currentFile.newFile = line;
    } else if (line.startsWith('@@')) {
      const match = line.match(/@@ -(\d+),?\d* \+(\d+),?\d* @@/);
      if (match && currentFile) {
        leftLine = parseInt(match[1]);
        rightLine = parseInt(match[2]);
        currentFile.hunks.push({
          header: line,
          lines: []
        });
      }
    } else if (currentFile && currentFile.hunks.length > 0) {
      const hunk = currentFile.hunks[currentFile.hunks.length - 1];
      
      if (line.startsWith('-')) {
        hunk.lines.push({
          type: 'removed',
          leftNum: leftLine++,
          rightNum: null,
          content: line.slice(1)
        });
      } else if (line.startsWith('+')) {
        hunk.lines.push({
          type: 'added',
          leftNum: null,
          rightNum: rightLine++,
          content: line.slice(1)
        });
      } else {
        hunk.lines.push({
          type: 'context',
          leftNum: leftLine++,
          rightNum: rightLine++,
          content: line.startsWith(' ') ? line.slice(1) : line
        });
      }
    }
  }
  
  if (currentFile) files.push(currentFile);
  return files;
}

function renderSideBySideHTML(input) {
  // First, score all lines for heatmap colors
  const parsed = parseDiff(input);
  const scored = scoreAllLines(parsed);
  
  // Detect language for highlighting
  const filename = extractFilename(parsed);
  const language = filename ? detectLanguage(filename) : 'unknown';
  
  // Build a map of line content to scores and reasons for lookup
  const scoreMap = new Map();
  for (const line of scored) {
    if (line.tag === 'Added') {
      scoreMap.set(line.text.trim(), { score: line.score, reasons: line.reasons });
    }
  }
  
  const files = parseSideBySide(input);
  let html = '<div class="container">';
  let rowId = 0;
  
  for (const file of files) {
    html += `<div class="file-header">${escapeHtml(file.header)}</div>`;
    
    for (const hunk of file.hunks) {
      html += `<div class="hunk-header">${escapeHtml(hunk.header)}</div>`;
      
      // Two side-by-side panels, each with its own scrollable content
      html += '<div class="diff-panels">';
      
      // Left panel (before)
      html += '<div class="diff-panel left-panel">';
      html += '<div class="panel-scroll">';
      html += '<table class="panel-table"><tbody>';
      
      const startRowId = rowId; // Save starting row ID for right panel
      for (const line of hunk.lines) {
        const leftNum = line.leftNum !== null ? line.leftNum : '';
        const leftClass = line.type === 'removed' ? 'removed' : '';
        const leftContent = line.type === 'removed' || line.type === 'context' 
          ? escapeHtml(line.content) : '';
        
        html += `<tr class="diff-row" data-row="${rowId}">`;
        html += `<td class="line-num" data-row="${rowId}">${leftNum}</td>`;
        html += `<td class="line-content ${leftClass}">${leftContent}</td>`;
        html += '</tr>';
        rowId++;
      }
      
      html += '</tbody></table>';
      html += '</div>'; // panel-scroll
      html += '</div>'; // left-panel
      
      // Right panel (after) - use same row IDs to match left panel
      html += '<div class="diff-panel right-panel">';
      html += '<div class="panel-scroll">';
      html += '<table class="panel-table"><tbody>';
      
      let rightRowId = startRowId; // Start from same ID as left panel
      for (const line of hunk.lines) {
        const rightNum = line.rightNum !== null ? line.rightNum : '';
        let rightClass = '';
        let rightContent = '';
        
        let titleAttr = '';
        if (line.type === 'added') {
          const scoreData = scoreMap.get(line.content.trim()) || { score: 0, reasons: [] };
          const bgColor = scoreToHeatmapColor(scoreData.score);
          const textColor = getTextColor(bgColor);
          rightContent = applyInlineHighlightsHTML(line.content, language);
          rightClass = `added" style="background-color: ${bgColor}; color: ${textColor};`;
          titleAttr = scoreData.reasons && scoreData.reasons.length > 0 
            ? ` title="${escapeHtml(scoreData.reasons.join('; '))}"` 
            : '';
        } else if (line.type === 'context') {
          rightContent = escapeHtml(line.content);
        }
        
        html += `<tr class="diff-row" data-row="${rightRowId}">`;
        html += `<td class="line-num" data-row="${rightRowId}">${rightNum}</td>`;
        html += `<td class="line-content ${rightClass}"${titleAttr}>${rightContent}</td>`;
        html += '</tr>';
        rightRowId++;
      }
      
      html += '</tbody></table>';
      html += '</div>'; // panel-scroll
      html += '</div>'; // right-panel
      
      html += '</div>'; // diff-panels
    }
  }
  
  html += '</div>';
  return html;
}

function generateHTMLPage(diffContent, isSideBySide = false) {
  const sideBySideStyles = isSideBySide ? `
    .container {
      padding: 0;
    }
    .file-header {
      background: #2d2d2d;
      padding: 8px 12px;
      color: #569cd6;
      font-weight: bold;
      border-bottom: 1px solid #333;
      margin-top: 20px;
    }
    .file-header:first-child {
      margin-top: 0;
    }
    .hunk-header {
      background: #252525;
      padding: 4px 12px;
      color: #888;
      font-size: 12px;
      border-bottom: 1px solid #333;
    }
    .diff-panels {
      display: flex;
      width: 100%;
      border-bottom: 1px solid #333;
    }
    .diff-panel {
      width: 50%;
      overflow-x: auto;
      overflow-y: hidden;
    }
    .left-panel {
      border-right: 2px solid #333;
    }
    .panel-scroll {
      min-width: min-content;
    }
    .panel-table {
      width: 100%;
      border-collapse: collapse;
    }
    .panel-table td {
      padding: 2px 8px;
      vertical-align: top;
      line-height: 1.2;
    }
    .line-num {
      width: 50px;
      min-width: 50px;
      text-align: right;
      color: #666;
      background: #252525;
      user-select: none;
      border-right: 1px solid #333;
      font-size: 11px;
      position: sticky;
      left: 0;
      z-index: 1;
    }
    .line-num:hover {
      background: #2d2d2d;
      color: #888;
    }
    .diff-row.hover-highlight {
      background: rgba(76, 201, 176, 0.05);
    }
    .diff-row.hover-highlight .line-num {
      background: #2d2d2d;
      color: #888;
    }
    .line-content {
      white-space: pre;
      font-size: 13px;
    }
    .removed {
      background: rgba(244, 135, 113, 0.15);
      color: #f48771;
    }
    .added {
      background: rgba(76, 201, 176, 0.1);
    }
    .added-high {
      background: rgba(244, 135, 113, 0.2);
      color: #f48771;
    }
    .added-medium {
      background: rgba(215, 186, 125, 0.15);
      color: #d7ba7d;
    }
    .added-low {
      background: rgba(76, 201, 176, 0.15);
      color: #4ec9b0;
    }
  ` : `
    .container {
      padding: 0;
    }
    .file-header {
      background: #2d2d2d;
      padding: 8px 12px;
      color: #569cd6;
      font-weight: bold;
      border-bottom: 1px solid #333;
      margin-top: 20px;
    }
    .file-header:first-child {
      margin-top: 0;
    }
    .diff-table.unified {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
    }
    .diff-table.unified td {
      padding: 2px 8px;
      vertical-align: top;
      line-height: 1.2;
    }
    .diff-table.unified .line-num {
      width: 50px;
      min-width: 50px;
      text-align: right;
      color: #666;
      background: #252525;
      user-select: none;
      border-right: 1px solid #333;
      font-size: 11px;
    }
    .diff-table.unified .line-content {
      white-space: pre;
      font-size: 13px;
      padding-left: 12px;
      overflow-x: auto;
      max-width: 0;
    }
    .hunk-header {
      background: #252525;
      padding: 4px 12px;
      color: #888;
      font-size: 12px;
      border-bottom: 1px solid #333;
    }
    .header { color: #569cd6; font-weight: bold; }
    .context { color: #d4d4d4; }
    .removed { 
      background: rgba(244, 135, 113, 0.15);
      color: #f48771;
    }
    .added-high { 
      background: rgba(244, 135, 113, 0.2);
      color: #f48771;
    }
    .added-medium { 
      background: rgba(215, 186, 125, 0.15);
      color: #d7ba7d;
    }
    .added-low { 
      background: rgba(76, 201, 176, 0.15);
      color: #4ec9b0;
    }
    .added-normal { 
      background: rgba(76, 201, 176, 0.1);
      color: #d4d4d4;
    }
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Diff Heatmap</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
      background: #1e1e1e;
      color: #d4d4d4;
      line-height: 1.2;
      padding: 20px;
      font-size: 13px;
    }
    pre {
      white-space: pre-wrap;
      word-wrap: break-word;
      line-height: 1.2;
    }
    ${sideBySideStyles}
    .hl-secret {
      background: #ff5555;
      color: white;
      padding: 2px 5px;
      border-radius: 3px;
      font-weight: bold;
      display: inline;
    }
    .hl-danger {
      background: #ff8800;
      color: black;
      padding: 2px 5px;
      border-radius: 3px;
      font-weight: bold;
      display: inline;
    }
    .hl-warning {
      background: #ffdd33;
      color: black;
      padding: 2px 5px;
      border-radius: 3px;
      font-weight: bold;
      display: inline;
    }
    .hl-complex {
      background: rgba(255, 221, 51, 0.3);
      padding: 1px 3px;
      border-radius: 2px;
      font-weight: bold;
      display: inline;
    }
  </style>
</head>
<body>
  ${diffContent}
  ${isSideBySide ? `
  <script>
    // Handle row highlighting on hover (across both panels)
    document.addEventListener('mouseover', (e) => {
      const lineNum = e.target.closest('.line-num');
      if (!lineNum || !lineNum.dataset.row) return;
      
      const rowId = lineNum.dataset.row;
      document.querySelectorAll(\`.diff-row[data-row="\${rowId}"]\`).forEach(row => {
        row.classList.add('hover-highlight');
      });
    });
    
    document.addEventListener('mouseout', (e) => {
      const lineNum = e.target.closest('.line-num');
      if (!lineNum || !lineNum.dataset.row) return;
      
      const rowId = lineNum.dataset.row;
      document.querySelectorAll(\`.diff-row[data-row="\${rowId}"]\`).forEach(row => {
        row.classList.remove('hover-highlight');
      });
    });
  </script>
  ` : ''}
</body>
</html>`;
}

// === URL Fetching ===

async function fetchURL(url) {
  const https = require('https');
  const http = require('http');
  
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith('https') ? https : http;
    
    protocol.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetchURL(res.headers.location).then(resolve).catch(reject);
      }
      
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function convertGitHubURL(url) {
  const prMatch = url.match(/github\.com\/([^\/]+)\/([^\/]+)\/pull\/(\d+)/);
  if (prMatch) {
    const [, owner, repo, prNumber] = prMatch;
    return `https://patch-diff.githubusercontent.com/raw/${owner}/${repo}/pull/${prNumber}.diff`;
  }
  return url;
}

// === Cleanup Functions ===

/**
 * Clean up temporary HTML files created by this program
 * Only removes files matching the pattern: /tmp/diff-heatmap-{timestamp}.html
 * Returns: {count: number, bytes: number, errors: string[]}
 */
function cleanupTempFiles() {
  const fs = require('fs');
  const path = require('path');
  const tmpDir = '/tmp';
  const pattern = /^diff-heatmap-\d+\.html$/;
  
  let count = 0;
  let bytes = 0;
  const errors = [];
  
  try {
    const files = fs.readdirSync(tmpDir);
    
    for (const file of files) {
      if (pattern.test(file)) {
        const filePath = path.join(tmpDir, file);
        try {
          const stats = fs.statSync(filePath);
          fs.unlinkSync(filePath);
          count++;
          bytes += stats.size;
        } catch (err) {
          errors.push(`Failed to delete ${file}: ${err.message}`);
        }
      }
    }
  } catch (err) {
    errors.push(`Failed to read ${tmpDir}: ${err.message}`);
  }
  
  return { count, bytes, errors };
}

// === Entry Point ===

async function main() {
  const args = process.argv.slice(2);
  const fs = require('fs');
  const { exec } = require('child_process');
  
  // Parse arguments
  let url = null;
  let filePath = null;
  let outputHTML = false;
  let openBrowser = false;
  let sideBySide = false;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--html') {
      outputHTML = true;
    } else if (args[i] === '--open' || args[i] === '-o') {
      outputHTML = true;
      openBrowser = true;
    } else if (args[i] === '--side-by-side' || args[i] === '-s') {
      sideBySide = true;
      outputHTML = true;  // Side-by-side only works with HTML output
    } else if (args[i] === '--url' && args[i + 1]) {
      url = args[++i];
    } else if (args[i].startsWith('http://') || args[i].startsWith('https://')) {
      url = args[i];
    } else if (args[i] === '--cleanup') {
      const result = cleanupTempFiles();
      if (result.count === 0) {
        console.log('No temporary files found to clean up.');
      } else {
        const kb = (result.bytes / 1024).toFixed(2);
        console.log(`Cleaned up ${result.count} temporary file${result.count === 1 ? '' : 's'} (${kb} KB)`);
      }
      if (result.errors.length > 0) {
        console.error('\nErrors:');
        result.errors.forEach(err => console.error(`  ${err}`));
        process.exit(1);
      }
      process.exit(0);
    } else if (args[i] === '--list-rules') {
      console.log(`
Diff Heatmap - Available Rules

The following security and code quality rules are checked:
`);
      for (const [ruleName, rule] of Object.entries(RULES)) {
        const langs = rule.languages ? ` [${rule.languages.join(', ')}]` : ' [all languages]';
        console.log(`\n${ruleName}${langs}`);
        console.log(`  Score: ${rule.score}`);
        for (const pattern of rule.patterns) {
          console.log(`  - ${pattern.desc}`);
        }
      }
      console.log('\nUse --help for usage information.\n');
      process.exit(0);
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`
Diff Heatmap - Colorize git diffs by what changes likely need the most attention

Usage:
  diff-heatmap [options] [file|url]
  git diff | diff-heatmap [options]

Options:
  --html              Output HTML instead of ANSI terminal colors
  --open, -o          Output HTML and open in browser
  --side-by-side, -s  Side-by-side view (HTML only, implies --html)
  --url <url>         Fetch diff from URL
  --cleanup           Remove all temporary HTML files created by --open
  --list-rules        List all available security/quality rules
  --help, -h          Show this help

Output Modes:
  Default:            Terminal output with ANSI colors
  --html:             Unified HTML view
  --side-by-side:     Split HTML view with line numbers (auto-enables --html)

Examples:
  # Terminal output (ANSI colors)
  git diff | node diff-heatmap.js
  
  # HTML unified view
  git diff | node diff-heatmap.js --html > output.html
  git diff | node diff-heatmap.js --open
  
  # HTML side-by-side view
  git diff | node diff-heatmap.js --side-by-side --open
  node diff-heatmap.js my-changes.diff -s -o
  
  # GitHub PR
  node diff-heatmap.js https://github.com/user/repo/pull/123 --open
  node diff-heatmap.js https://github.com/user/repo/pull/123 -s -o
  
  # Cleanup temporary files
  node diff-heatmap.js --cleanup
      `);
      process.exit(0);
    } else if (!args[i].startsWith('-')) {
      // Non-option argument is treated as a file path
      filePath = args[i];
    }
  }
  
  let input = '';
  
  // Fetch from URL if provided
  if (url) {
    try {
      const convertedURL = convertGitHubURL(url);
      console.error(`Fetching from ${convertedURL}...`);
      input = await fetchURL(convertedURL);
    } catch (error) {
      console.error(`Error fetching URL: ${error.message}`);
      process.exit(1);
    }
  } else if (filePath) {
    // Read from file
    try {
      input = fs.readFileSync(filePath, 'utf8');
    } catch (error) {
      console.error(`Error reading file: ${error.message}`);
      process.exit(1);
    }
  } else {
    // Read from stdin
    if (process.stdin.isTTY) {
      console.error('Error: No input provided. Use --help for usage information.');
      process.exit(1);
    }
    
    await new Promise((resolve, reject) => {
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => input += chunk);
      process.stdin.on('end', resolve);
      process.stdin.on('error', reject);
    });
  }
  
  // Check for empty input
  if (!input || input.trim().length === 0) {
    console.error('Error: No diff input received. Make sure you have uncommitted changes when using "git diff".');
    console.error('Try: git status (to check for changes) or git diff (to see the diff)');
    process.exit(1);
  }
  
  // Process the diff using functional pipeline
  // For terminal output: input > parse > score > render
  // For HTML output: input > (parse > score > renderHTML) OR renderSideBySide
  
  if (outputHTML) {
    const htmlContent = sideBySide 
      ? renderSideBySideHTML(input)
      : pipe(parseDiff, scoreAllLines, renderDiffHTML)(input)
    
    const fullHTML = generateHTMLPage(htmlContent, sideBySide)
    
    if (openBrowser) {
      // Create temporary file for browser viewing
      // Pattern: /tmp/diff-heatmap-{timestamp}.html
      // These files persist after the program exits to allow browser viewing
      // Use --cleanup flag to remove old temp files
      const tempFile = `/tmp/diff-heatmap-${Date.now()}.html`
      fs.writeFileSync(tempFile, fullHTML)
      console.error(`Opening in browser: ${tempFile}`)
      exec(`open "${tempFile}"`, (error) => {
        if (error) {
          console.error(`Error opening browser: ${error.message}`)
        }
      })
    } else {
      console.log(fullHTML)
    }
  } else {
    // Terminal output pipeline: parse > score > render
    const output = pipe(parseDiff, scoreAllLines, renderDiff)(input)
    console.log(output)
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error('Fatal error:', err.message);
    process.exit(1);
  });
}

module.exports = { 
  parseDiff, 
  scoreLine,
  scoreAllLines,
  scoreToColor, 
  processDiff,
  applyInlineHighlights,
  detectLanguage,
  scoreWithRules,
  parseSideBySide,
  renderDiffHTML,
  renderSideBySideHTML,
  RULES
}
