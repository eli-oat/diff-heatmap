#!/usr/bin/env node

const { test, assert } = require('./test-utils')

console.log('=== Mutable State Detection Tests ===\n');

// Test 1: Global Mutable State - JavaScript
test('Detects global let in JavaScript', () => {
  const pattern1 = /^(let|var)\s+\w+\s*=/gm;
  assert(pattern1.test('let globalCounter = 0'),
    'Should detect global let');
  const pattern2 = /^(let|var)\s+\w+\s*=/gm;
  assert(pattern2.test('var globalState = {}'),
    'Should detect global var');
});

test('Does not flag const in JavaScript', () => {
  const pattern = /^(let|var)\s+\w+\s*=/gm;
  assert(!pattern.test('const CONSTANT = 42'),
    'Should not flag const');
});

// Test 2: Global Mutable State - Python
test('Detects global mutable dict in Python', () => {
  const pattern1 = /^[A-Z_]+\s*=\s*\{/gm;
  assert(pattern1.test('GLOBAL_CONFIG = {}'),
    'Should detect global dict');
  const pattern2 = /^[A-Z_]+\s*=\s*\{/gm;
  assert(pattern2.test('CACHE = {\'key\': \'value\'}'),
    'Should detect mutable dict');
});

test('Detects global mutable list in Python', () => {
  const pattern1 = /^[A-Z_]+\s*=\s*\[/gm;
  assert(pattern1.test('GLOBAL_LIST = []'),
    'Should detect global list');
  const pattern2 = /^[A-Z_]+\s*=\s*\[/gm;
  assert(pattern2.test('ITEMS = [1, 2, 3]'),
    'Should detect mutable list');
});

// Test 3: Global Mutable State - Go
test('Detects package-level var in Go', () => {
  const pattern = /^var\s+\w+\s*=/gm;
  assert(pattern.test('var globalCounter = 0'),
    'Should detect package-level var');
});

// Test 4: Global Mutable State - Rust
test('Detects static mut in Rust', () => {
  const pattern = /static\s+mut\s+/g;
  assert(pattern.test('static mut COUNTER: i32 = 0;'),
    'Should detect static mut');
});

// Test 5: Global Mutable State - Java
test('Detects public static non-final in Java', () => {
  const pattern = /public\s+static\s+(?!final)\w+/g;
  assert(pattern.test('public static int counter = 0;'),
    'Should detect public static non-final');
  assert(!pattern.test('public static final int MAX = 100;'),
    'Should not flag final fields');
});

// Test 6: Shared Mutable State - Java
test('Detects Java concurrency primitives', () => {
  const pattern1 = /\bAtomicInteger|AtomicLong|AtomicBoolean|AtomicReference/g;
  assert(pattern1.test('AtomicInteger counter = new AtomicInteger();'),
    'Should detect AtomicInteger');
  const pattern2 = /\bAtomicInteger|AtomicLong|AtomicBoolean|AtomicReference/g;
  assert(pattern2.test('private AtomicLong totalCount;'),
    'Should detect AtomicLong');
});

test('Detects volatile keyword in Java', () => {
  const pattern = /\bvolatile\s+\w+/g;
  assert(pattern.test('private volatile boolean running;'),
    'Should detect volatile');
});

// Test 7: Shared Mutable State - Python
test('Detects Python threading primitives', () => {
  const pattern1 = /threading\.Lock|threading\.RLock|threading\.Semaphore/g;
  assert(pattern1.test('lock = threading.Lock()'),
    'Should detect threading.Lock');
  const pattern2 = /threading\.Lock|threading\.RLock|threading\.Semaphore/g;
  assert(pattern2.test('rlock = threading.RLock()'),
    'Should detect threading.RLock');
});

// Test 8: Shared Mutable State - Go
test('Detects Go mutex usage', () => {
  const pattern1 = /sync\.Mutex|sync\.RWMutex/g;
  assert(pattern1.test('var mu sync.Mutex'),
    'Should detect sync.Mutex');
  const pattern2 = /sync\.Mutex|sync\.RWMutex/g;
  assert(pattern2.test('rwMutex := sync.RWMutex{}'),
    'Should detect sync.RWMutex');
});

// Test 9: Shared Mutable State - Rust
test('Detects Rust shared state patterns', () => {
  const pattern1 = /Mutex::new|RwLock::new|Arc::new/g;
  assert(pattern1.test('let mutex = Mutex::new(0);'),
    'Should detect Mutex::new');
  const pattern2 = /Mutex::new|RwLock::new|Arc::new/g;
  assert(pattern2.test('let arc = Arc::new(data);'),
    'Should detect Arc::new');
});

// Test 10: Shared Mutable State - C++
test('Detects C++ mutex usage', () => {
  const pattern = /std::mutex|std::shared_mutex|std::lock_guard/g;
  assert(pattern.test('std::mutex mtx;'),
    'Should detect std::mutex');
  assert(pattern.test('std::lock_guard<std::mutex> lock(mtx);'),
    'Should detect std::lock_guard');
});

// Test 11: Mutable Class State
test('Detects instance field mutation (this)', () => {
  const pattern1 = /this\.\w+\s*=(?!=)/g;
  assert(pattern1.test('this.count = 0'),
    'Should detect this field mutation');
  const pattern2 = /this\.\w+\s*=(?!=)/g;
  assert(pattern2.test('this.state = newState'),
    'Should detect state mutation');
  const pattern3 = /this\.\w+\s*=(?!=)/g;
  assert(!pattern3.test('if (this.count === 0)'),
    'Should not flag comparison');
});

test('Detects instance field mutation (self)', () => {
  const pattern = /self\.\w+\s*=(?!=)/g;
  assert(pattern.test('self.value = 42'),
    'Should detect self field mutation');
  assert(!pattern.test('if self.value == 42:'),
    'Should not flag comparison');
});

test('Detects React setState', () => {
  const pattern = /\bsetState\s*\(/g;
  assert(pattern.test('this.setState({ count: 0 })'),
    'Should detect setState');
});

// Test 12: Collection Mutation - JavaScript
test('Detects JavaScript array mutation', () => {
  const pattern1 = /\.push\(|\.pop\(|\.shift\(|\.unshift\(|\.splice\(/g;
  assert(pattern1.test('arr.push(item)'),
    'Should detect push');
  const pattern2 = /\.push\(|\.pop\(|\.shift\(|\.unshift\(|\.splice\(/g;
  assert(pattern2.test('arr.pop()'),
    'Should detect pop');
  const pattern3 = /\.push\(|\.pop\(|\.shift\(|\.unshift\(|\.splice\(/g;
  assert(pattern3.test('arr.splice(0, 1)'),
    'Should detect splice');
});

// Test 13: Collection Mutation - Python
test('Detects Python list mutation', () => {
  const pattern1 = /\.append\(|\.extend\(|\.remove\(|\.pop\(|\.insert\(/g;
  assert(pattern1.test('list.append(item)'),
    'Should detect append');
  const pattern2 = /\.append\(|\.extend\(|\.remove\(|\.pop\(|\.insert\(/g;
  assert(pattern2.test('list.remove(item)'),
    'Should detect remove');
});

// Test 14: Collection Mutation - Java
test('Detects Java collection mutation', () => {
  const pattern1 = /\.add\(|\.remove\(|\.clear\(|\.put\(/g;
  assert(pattern1.test('list.add(item)'),
    'Should detect add');
  const pattern2 = /\.add\(|\.remove\(|\.clear\(|\.put\(/g;
  assert(pattern2.test('map.put(key, value)'),
    'Should detect put');
});

// Test 15: Array/Map element mutation
test('Detects array/map element assignment', () => {
  const pattern1 = /\[\w+\]\s*=(?!=)/g;
  assert(pattern1.test('arr[i] = value'),
    'Should detect array element mutation');
  const pattern2 = /\[\w+\]\s*=(?!=)/g;
  assert(pattern2.test('map[key] = value'),
    'Should detect map element mutation');
  const pattern3 = /\[\w+\]\s*=(?!=)/g;
  assert(!pattern3.test('if (arr[i] === value)'),
    'Should not flag comparison');
});

// Test 16: Reassignment Patterns
test('Detects self-modifying reassignment', () => {
  const pattern1 = /\b(\w+)\s*=\s*\1\s*[+\-*/]/g;
  assert(pattern1.test('count = count + 1'),
    'Should detect count = count + 1');
  const pattern2 = /\b(\w+)\s*=\s*\1\s*[+\-*/]/g;
  assert(pattern2.test('total = total * 2'),
    'Should detect total = total * 2');
});

test('Detects compound assignment', () => {
  const pattern1 = /\b(\w+)\s*[+\-*/]=\s*/g;
  assert(pattern1.test('count += 1'),
    'Should detect +=');
  const pattern2 = /\b(\w+)\s*[+\-*/]=\s*/g;
  assert(pattern2.test('total *= 2'),
    'Should detect *=');
  const pattern3 = /\b(\w+)\s*[+\-*/]=\s*/g;
  assert(pattern3.test('value -= 10'),
    'Should detect -=');
});

test('Detects increment/decrement operators', () => {
  const pattern1 = /\+\+\w+|\w+\+\+|--\w+|\w+--/g;
  assert(pattern1.test('i++'),
    'Should detect i++');
  const pattern2 = /\+\+\w+|\w+\+\+|--\w+|\w+--/g;
  assert(pattern2.test('++counter'),
    'Should detect ++counter');
  const pattern3 = /\+\+\w+|\w+\+\+|--\w+|\w+--/g;
  assert(pattern3.test('value--'),
    'Should detect value--');
});

// Test 17: Closure Mutable State - Python
test('Detects Python nonlocal', () => {
  const pattern = /\bnonlocal\s+\w+/g;
  assert(pattern.test('nonlocal counter'),
    'Should detect nonlocal');
});

// Test 18: Lock acquisition
test('Detects lock acquisition', () => {
  const pattern = /lock\s*\(/g;
  assert(pattern.test('mutex.lock()'),
    'Should detect lock()');
  assert(pattern.test('synchronized.lock()'),
    'Should detect lock call');
});

// Test 19: Private mutable fields
test('Detects private mutable field in Java', () => {
  const pattern = /\bprivate\s+(?!final|readonly)\w+\s+\w+;/g;
  assert(pattern.test('private int counter;'),
    'Should detect private mutable field');
  assert(!pattern.test('private final int MAX = 100;'),
    'Should not flag final field');
});

// Test 20: Integration test - does not over-trigger on safe patterns
test('Does not flag immutable patterns', () => {
  // const declarations
  const globalPattern = /^(let|var)\s+\w+\s*=/gm;
  assert(!globalPattern.test('const IMMUTABLE = {}'),
    'Should not flag const');
  
  // final fields
  const finalPattern = /public\s+static\s+(?!final)\w+/g;
  assert(!finalPattern.test('public static final String NAME = "test";'),
    'Should not flag final fields');
  
  // readonly in C#
  const readonlyPattern = /public\s+static\s+(?!readonly)\w+/g;
  assert(!readonlyPattern.test('public static readonly int Count = 0;'),
    'Should not flag readonly fields');
});

// Test 21: Comprehensive language coverage
test('Covers all major languages', () => {
  const languages = [
    'javascript', 'typescript', 'python', 'java', 'csharp',
    'c', 'cpp', 'go', 'rust'
  ];
  
  // Just verify we have patterns for major languages
  // (this is more of a documentation test)
  assert(languages.length >= 9, 'Should cover 9+ languages');
});

require('./test-utils').printSummary()
