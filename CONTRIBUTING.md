# Contributing to ReversibleAI

Thank you for your interest in contributing to ReversibleAI!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/reversibleai.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Install in development mode: `pip install -e .[dev]`
5. Install pre-commit hooks: `pre-commit install`

## Code Style

We use:
- **Black** for code formatting (line length: 88)
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run before committing:
```bash
black reversibleai tests
isort reversibleai tests
flake8 reversibleai tests
mypy reversibleai
```

## Testing

- Write tests for new features
- Ensure all tests pass: `pytest`
- Maintain test coverage above 80%

## Submitting Changes

1. Ensure all tests pass
2. Update documentation if needed
3. Commit: `git commit -m 'Add feature: description'`
4. Push: `git push origin feature/your-feature-name`
5. Open a Pull Request

## Code Review

All contributions require code review. Please be patient and responsive to feedback.
