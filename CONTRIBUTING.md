# Contributing to ComplianceStack

Thank you for your interest in contributing to ComplianceStack! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Docker 24+** and **Docker Compose v2**
- **Python 3.12** (for backend development)
- **Node.js 20+** (for MCP server development)
- **Git**

### Development Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone
   git clone https://github.com/YOUR_USERNAME/ComplianceStack.git
   cd ComplianceStack
   ```

2. **Start the development environment**
   ```bash
   cp .env.example .env
   docker compose up --build -d
   ```

3. **Verify services are running**
   ```bash
   curl http://localhost:8000/health
   ```

### Backend Development

```bash
cd python-backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run linting
ruff check .

# Run type checking
mypy .
```

### MCP Server Development

```bash
cd mcp-server
npm install

# Build
npm run build

# Development mode (with hot reload)
npm run dev

# Type checking
npm run typecheck
```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include screenshots if possible**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Explain why this enhancement would be useful**
- **Include examples of how the enhancement would work**

### Contributing Code

1. **Create a feature branch** from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the coding standards below
   - Add tests for new functionality
   - Update documentation as needed

3. **Commit your changes**
   ```bash
   git commit -m "feat: add new feature description"
   ```

4. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request**

## Pull Request Process

1. **Update the README.md** with details of changes if applicable
2. **Update the CHANGELOG.md** with a new entry under "Unreleased"
3. **Ensure all tests pass** (`pytest tests/` for Python, `npm test` for MCP server)
4. **Ensure code passes linting** (`ruff check .` for Python)
5. **Request review** from maintainers

### PR Title Convention

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, missing semi-colons, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

Examples:
- `feat: add bias assessment for protected attributes`
- `fix: resolve MCP server connection timeout`
- `docs: update API reference for DPIA endpoint`

## Coding Standards

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/) style guide
- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions focused and small (under 50 lines when possible)
- Use meaningful variable and function names

### TypeScript

- Follow the [TypeScript Style Guide](https://typescript-eslint.io/)
- Use strict TypeScript configuration
- Write JSDoc comments for complex functions
- Prefer `interface` over `type` for object shapes
- Use async/await over raw promises

### General

- Write self-documenting code with clear naming
- Add comments for complex logic
- Keep functions focused on a single responsibility
- Write tests for new functionality
- Update documentation when changing APIs

## Testing

### Python Backend

```bash
cd python-backend

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_bias.py -v

# Run with coverage
pytest tests/ --cov=.
```

### MCP Server

```bash
cd mcp-server

# Run build
npm run build

# Type check
npm run typecheck
```

### Integration Tests

```bash
# Start all services
docker compose up --build -d

# Run integration tests
pytest tests/ -m integration
```

## Documentation

- Update README.md for new features or API changes
- Add docstrings to all new functions and classes
- Update API documentation for new endpoints
- Include examples in documentation
- Keep CHANGELOG.md updated

## NOTICE File & Attribution

The repository contains a [NOTICE](./NOTICE) file at the root. **Do not delete or modify it** — Apache 2.0 requires all redistributors to include this file (or its contents) in their distribution. It serves as the primary attribution mechanism for this project. When forking, keep the NOTICE file intact.

## Community

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Pull Requests**: For code contributions

## Questions?

If you have questions about contributing, please open a GitHub issue with the label "question".

Thank you for contributing to ComplianceStack! 🎉
