# Contributing to HeaderSentinel

Thank you for your interest in contributing to HeaderSentinel! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Provide constructive feedback
- Report security vulnerabilities responsibly
- Focus on authorized security testing only

## How to Contribute

### 1. Reporting Bugs

**Before submitting a bug report:**
- Check if the bug has already been reported
- Try to reproduce the issue
- Collect relevant information

**When submitting:**
- Use a clear, descriptive title
- Provide steps to reproduce
- Include actual vs. expected behavior
- Share your environment (OS, Python/Node version)

### 2. Suggesting Enhancements

**Before suggesting:**
- Check existing issues and pull requests
- Ensure it aligns with project goals

**When suggesting:**
- Use a clear title
- Provide detailed description
- Explain use cases and benefits
- List examples if applicable

### 3. Pull Requests

#### Setup Development Environment
```bash
# Clone your fork
git clone https://github.com/yourusername/HeaderSentinel.git
cd HeaderSentinel

# Create feature branch
git checkout -b feature/your-feature-name
```

#### Making Changes

**Backend Changes:**
- Follow PEP 8 style guide
- Add type hints for function parameters
- Write docstrings for classes and functions
- Add tests for new functionality
- Update requirements.txt if adding dependencies

**Frontend Changes:**
- Follow ESLint configuration
- Use TypeScript for type safety
- Component-based structure
- Add PropTypes or TypeScript types
- Test in multiple browsers

#### Testing
```bash
# Backend
cd backend
pytest -v --cov=app

# Frontend
cd frontend
npm run type-check
npm test  # When tests are added
```

#### Commit Message Format
```
Type: Short description (50 chars)

Longer description explaining what and why (wrap at 72 chars).

- Bullet points for complex changes
- Keep commits atomic and focused

Fixes #123  # If closing an issue
```

Types: feat, fix, docs, style, refactor, perf, test, chore

#### Push and Create PR
```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

**PR Description:**
- Reference related issues
- Describe changes clearly
- List testing steps
- Include screenshots if UI changes

### 4. Documentation

Improve documentation by:
- Fixing typos and clarity
- Adding examples
- Creating tutorials
- Translating docs

---

## Development Guidelines

### Code Style

**Python:**
- Use Black for formatting
- Use mypy for type checking
- Follow PEP 8
- Max line length: 100

```bash
pip install black mypy

black app/
mypy app/
```

**TypeScript/React:**
- Use Prettier for formatting
- Follow ESLint rules
- Use TypeScript strict mode

```bash
npm install prettier eslint

npx prettier --write src/
npx eslint src/
```

### Testing Requirements

- Write tests for all new features
- Maintain >80% code coverage
- Test edge cases
- Use meaningful test names

**Backend Example:**
```python
def test_csp_missing_detection():
    """Test that missing CSP is detected."""
    headers = {}
    findings = analyze_csp(headers)
    assert any(f.severity == "HIGH" for f in findings)
```

### Performance

- Minimize API calls
- Optimize database queries
- Avoid N+1 queries
- Use caching appropriately

### Security

- Never commit secrets or credentials
- Use parameterized queries
- Validate all inputs
- Keep dependencies updated

---

## Project Structure

```
HeaderSentinel/
├── backend/
│   ├── app/
│   │   ├── analyzers/     # Header analysis modules
│   │   ├── security/      # SSRF, redaction, validation
│   │   ├── services/      # Business logic
│   │   └── ...
│   ├── tests/             # Test suite
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── services/      # API clients
│   │   ├── types/         # TypeScript types
│   │   └── ...
│   └── package.json
```

---

## Adding New Features

### Adding a New Header Analyzer

1. Create analyzer file: `backend/app/analyzers/new_header_analyzer.py`

```python
def analyze_new_header(headers: Dict[str, str]) -> List[Finding]:
    """Analyze new security header."""
    findings = []
    
    # Implementation
    
    return findings
```

2. Register in `header_analyzer.py`:
```python
from app.analyzers.new_header_analyzer import analyze_new_header

# In HeaderAnalyzer.analyze():
self.findings.extend(analyze_new_header(self.headers))
```

3. Add tests in `tests/test_header_analyzer.py`

4. Update README.md with new header documentation

### Adding a New Frontend Page

1. Create component: `frontend/src/app/newpage/page.tsx`
2. Add to sidebar: `frontend/src/components/Sidebar.tsx`
3. Update types: `frontend/src/types/index.ts`
4. Test navigation and functionality

---

## Review Process

1. **Automated Checks**
   - Run on all PRs
   - Must pass tests
   - Must pass linting

2. **Code Review**
   - At least one maintainer review
   - Constructive feedback
   - Address comments

3. **Approval**
   - Ready for merge
   - Squash commits (typically)
   - PR merged to main

---

## Release Process

Maintainers follow semantic versioning:
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

---

## Community

- **Discussions**: GitHub Discussions
- **Security**: security@headersent.com (responsibly disclosed)
- **Email**: [Contact information]

---

## Resources

- [Python PEP 8 Style Guide](https://pep8.org/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [React Documentation](https://react.dev/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---

Thank you for contributing to HeaderSentinel! 🎉
