# Contributing

Thanks for helping improve AgentScan.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

## Rule Guidelines

Good rules should be:

- specific enough to avoid noisy reports
- explainable in one sentence
- covered by tests
- paired with clear remediation

Avoid checks that require sending source code or secrets to third-party services. AgentScan should stay local-first by default.
