# Contributing to Parachute

Thank you for your interest in contributing to Parachute! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/parachute-security/parachute/issues)
2. If not, create a new issue using the bug report template
3. Include:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Go version, Docker version)

### Suggesting Features

1. Check existing [Issues](https://github.com/parachute-security/parachute/issues) and [Discussions](https://github.com/parachute-security/parachute/discussions)
2. Open a feature request issue with:
   - Clear use case description
   - Proposed solution (if any)
   - Alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Run tests: `make test-unit`
5. Commit with clear messages: `git commit -m "feat: add new feature"`
6. Push to your fork: `git push origin feature/your-feature-name`
7. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/parachute.git
cd parachute

# Install dependencies
go mod download

# Build
make build

# Run tests
make test-unit

# Run integration tests (requires Docker)
make test-integration

# Run locally
cp parachute.example.yaml parachute.yaml
export PARACHUTE_PASSWORD="dev-password"
./build/parachute --config parachute.yaml
```

## Code Style

- Follow standard Go conventions (`gofmt`, `golint`)
- Write tests for new functionality
- Keep functions focused and small
- Add comments for exported functions
- Use meaningful variable names

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

## Questions?

- Open a [Discussion](https://github.com/parachute-security/parachute/discussions)
- Check the [Documentation](https://github.com/parachute-security/parachute#readme)

Thank you for contributing! 🪂
