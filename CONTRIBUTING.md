# Contributing to icod-js

Thank you for your interest in contributing to icod-js! This document provides guidelines for contributing to the project.

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/icod-js.git
   cd icod-js
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Running Tests
```bash
npm test
```

### Type Checking
```bash
npm run typecheck
```

### Building
```bash
npm run build
```

### Development Mode (Watch)
```bash
npm run dev
```

## Code Standards

- Write TypeScript, not JavaScript
- All functions must have proper type annotations
- Export types for all public APIs
- Use meaningful variable and function names
- Add JSDoc comments for all exported functions

## Testing

- All new features must include tests
- All bug fixes must include regression tests
- Tests should cover both success and error cases
- Aim for comprehensive test coverage

## Security

Given the security-sensitive nature of this library:
- Never log or expose sensitive data (passphrases, keys)
- Always use constant-time comparisons for security-critical operations
- Follow Web Crypto API best practices
- Consider timing attacks and side-channel vulnerabilities

## Pull Request Process

1. Ensure all tests pass locally
2. Update documentation if needed
3. Add your changes to the CHANGELOG (if one exists)
4. Submit a pull request with a clear description
5. Wait for code review and address feedback

## Commit Messages

Follow conventional commit format:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `chore:` Build process or auxiliary tool changes

Example: `feat: add support for custom PBKDF2 iterations`

## Questions?

If you have questions about contributing, please open an issue for discussion.