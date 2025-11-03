# diff-heatmap

I saw [0github.com](https://0github.com/). I thought that it was compelling, but also it kinda shocked me that it needs to spin up a VM and run an LLM over the diff to create each view. It also totally leaves the rules of how to create the heat map grading up to the LLM as far as I could tell, so it isn't deterministic. This project does the same thing locally, without 3rd party dependencies, or using anyone else's computer all while have a clearly defined set of rules, meaning you know what you are gonna get every time you run it.

[Here's a blog post with some more info in it.](https://eli.li/but-i-can-do-that-with-regex)

## Install it

```bash
chmod +x diff-heatmap.js
ln -s $(pwd)/diff-heatmap.js /usr/local/bin/diff-heatmap
```

## Use it 

For the terminal (kinda lame, tbh)
```bash
git diff | diff-heatmap
git diff main..feature-branch | diff-heatmap
```

Beautiful HTML view (very awesome, not lame)
```bash
git diff | diff-heatmap --open
diff-heatmap https://github.com/simonw/datasette/pull/2548 --open
```

Absolutely most useful, side-by-side HTML view (ngl, 10/10, this is what should probably be the default)
```bash
git diff | diff-heatmap --side-by-side --open
diff-heatmap https://github.com/simonw/datasette/pull/2548 -s -o
```

Available flags include, 

```
--html              Output HTML (unified view)
--open, -o          Generate HTML and open in browser
--side-by-side, -s  Split view with line numbers (HTML only)
--cleanup           Remove all temporary HTML files
--list-rules        Show all detection patterns
--help, -h          Show help
```

When you use `--open`, temporary HTML files are created in `/tmp/diff-heatmap-{timestamp}.html`. These files persist after the program exits. Use `--cleanup` to remove them if you wanna,

```bash
diff-heatmap --cleanup
```

## Understand it

This program isn't super duper clever, it uses regex patterns to apply scores to the lines of a diff that are used to generate the color coding.

1. Parses git diff line by line
2. Scores each added line using regex patterns
3. Colors output based on risk score (0.0 = safe, 1.0 = critical)
4. Highlights specific dangerous patterns inline

The rules look for stuff like, 

- Hardcoded secrets (API keys, tokens, passwords)
- Deserialization vulnerabilities (Java, Python, PHP)
- Buffer overflows (C/C++)
- SQL injection (all languages)
- XSS vectors (HTML, JavaScript, React)
- Command injection (shell, PHP)
- Prototype pollution (JavaScript)
- XXE attacks (XML parsers)
- SSRF patterns (HTTP clients)
- Memory safety issues (use-after-free, double-free)
- Removed focus outlines (CSS outline: none)
- Missing alt text on images
- Missing ARIA labels on inputs/buttons
- Incorrect ARIA attribute usage
- ARIA relationships without matching IDs
- `onClick` handlers without keyboard support
- Positive `tabindex` values (breaks tab order)
- Non-semantic HTML (div/span as buttons)
- Missing labels on form elements
- Skipped heading levels
- Non-descriptive link text
- Missing iframe titles
- Disabled viewport zoom
- Auto-playing media
- Mutable global state
- Shared state in concurrent code
- Collection mutations
- Complex conditionals
- Resource leaks

Examples of this program in action, 

For reviewing a pull request, 
```bash
diff-heatmap https://github.com/simonw/datasette/pull/2548 -s -o
```

For checking work before committing, 
```bash
git diff | diff-heatmap
```

For comapring branches to one another, 
```bash
git diff main..feature | diff-heatmap --open
```

For auditing secrets in history,
```bash
git log -p --all | diff-heatmap | grep -C3 "secret"
```

## Test it

Run all tests,
```bash
node tests/run-all.js
```
Run individual tests,
```bash
node tests/test-critical-patterns.js    # Security pattern detection
node tests/test-mutable-state.js        # Mutable state patterns
node tests/test-new-features.js         # Language detection & HTML rendering
etc...
```

## Extend it

To add/modify/extend you can modify the `RULES` object at the top of `diff-heatmap.js`,

```javascript
my_custom_rule: {
  score: 0.85,
  highlightClass: 'danger',
  languages: ['python'],
  patterns: [
    { regex: /dangerous_pattern/g, desc: 'Description' }
  ]
}
```
