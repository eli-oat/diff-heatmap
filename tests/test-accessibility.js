const { scoreWithRules, RULES } = require('../diff-heatmap.js');

const tests = [
  {
    name: 'Outline removal',
    code: 'outline: none;',
    language: 'css',
    expectedRule: 'accessibility_critical'
  },
  {
    name: 'Image without alt',
    code: '<img src="logo.png">',
    language: 'html',
    expectedRule: 'accessibility_critical'
  },
  {
    name: 'Empty alt text',
    code: '<img src="logo.png" alt="">',
    language: 'html',
    expectedRule: 'accessibility_critical'
  },
  {
    name: 'Button with only icon',
    code: '<button><svg></svg></button>',
    language: 'html',
    expectedRule: 'accessibility_critical'
  },
  {
    name: 'Positive tabindex',
    code: '<div tabindex="5">Click me</div>',
    language: 'html',
    expectedRule: 'accessibility_critical'
  },
  {
    name: 'ARIA on presentation role',
    code: '<div role="presentation" aria-label="test">',
    language: 'html',
    expectedRule: 'accessibility_aria_issues'
  },
  {
    name: 'Redundant role on button',
    code: '<button role="button">Click</button>',
    language: 'html',
    expectedRule: 'accessibility_aria_issues'
  },

  {
    name: 'onClick without keyboard support',
    code: 'onClick={() => handleClick()}',
    language: 'javascript',
    expectedRule: 'accessibility_keyboard_issues'
  },
  {
    name: 'onclick on div without keyboard',
    code: '<div onclick="doSomething()">Click</div>',
    language: 'html',
    expectedRule: 'accessibility_keyboard_issues'
  },
  {
    name: 'tabindex without role',
    code: '<div tabindex="0">Content</div>',
    language: 'html',
    expectedRule: 'accessibility_keyboard_issues'
  },
  {
    name: 'mouseover without focus',
    code: '<div onmouseover="show()">Hover</div>',
    language: 'html',
    expectedRule: 'accessibility_keyboard_issues'
  },
  {
    name: 'div as button',
    code: '<div role="button" onclick="submit()">Submit</div>',
    language: 'html',
    expectedRule: 'accessibility_semantic_html'
  },
  {
    name: 'Skipped heading level',
    code: '<h1>Title</h1><h3>Subtitle</h3>',
    language: 'html',
    expectedRule: 'accessibility_semantic_html'
  },
  {
    name: 'Link with no text',
    code: '<a href="/page"></a>',
    language: 'html',
    expectedRule: 'accessibility_semantic_html'
  },
  {
    name: 'Non-descriptive link text',
    code: '<a href="/more">click here</a>',
    language: 'html',
    expectedRule: 'accessibility_semantic_html'
  },
  {
    name: 'html without lang',
    code: '<html><head><title>Test</title></head></html>',
    language: 'html',
    expectedRule: 'accessibility_content_issues'
  },
  {
    name: 'iframe without title',
    code: '<iframe src="https://example.com"></iframe>',
    language: 'html',
    expectedRule: 'accessibility_content_issues'
  },
  {
    name: 'Viewport zoom disabled',
    code: '<meta name="viewport" content="width=device-width, user-scalable=no">',
    language: 'html',
    expectedRule: 'accessibility_content_issues'
  },
  {
    name: 'aria-invalid without description',
    code: '<input type="text" aria-invalid="true">',
    language: 'html',
    expectedRule: 'accessibility_content_issues'
  }
];

console.log('Running accessibility rule tests...\n');

let passed = 0;
let failed = 0;

for (const test of tests) {
  const result = scoreWithRules(test.code, test.language);
  const matchedRule = Object.entries(RULES).find(([name, rule]) => {
    return rule.patterns.some(p => {
      p.regex.lastIndex = 0;
      return p.regex.test(test.code);
    }) && name === test.expectedRule;
  });
  
  if (result.score > 0 && matchedRule) {
    console.log(`✓ ${test.name}`);
    console.log(`  Score: ${result.score}, Reasons: ${result.reasons.join(', ')}`);
    passed++;
  } else {
    console.log(`✗ ${test.name}`);
    console.log(`  Expected rule: ${test.expectedRule}`);
    console.log(`  Got score: ${result.score}, Reasons: ${result.reasons.join(', ')}`);
    failed++;
  }
  console.log();
}

console.log(`\nPassed: ${passed}`);
console.log(`Failed: ${failed}`);
process.exit(failed > 0 ? 1 : 0);
