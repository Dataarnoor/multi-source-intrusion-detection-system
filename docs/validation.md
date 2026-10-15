# Validation

Checked on 16 October 2026 with Python 3.13.9 and psutil 7.1.3 on Linux.

Command: `python3 main.py`

The full suite completed successfully with all 10 attack scenarios detected. The benign noise scenario had no expected matching rule and is excluded from attack TP/FN counts; its console result is labelled `MISSED` by the sentinel-based runner.

| Metric | Result |
| --- | --- |
| True positives | 10 |
| False positives under the primary-rule evaluator | 7 |
| False negatives | 0 |
| Total alerts | 17 |
| Precision | 0.5882 |
| Recall | 1.0 |
| F1 | 0.7407 |
| Average / maximum latency | 1.209 / 3.415 seconds |
| Average / peak CPU | 0.56% / 8.0% |
| Average / peak memory | 21.93 / 22.03 MB |
| Wall time | 106.6 seconds |

All Python files parsed successfully. Source files match the original project copy. Generated logs and bytecode are excluded from Git. Results describe the simulated experiment suite and this machine only.
