# SentinelKit

An open-source, modular, defensive cybersecurity toolkit for Linux, Kali Linux, Parrot OS, and small Linux computers such as Orange Pi.

SentinelKit is designed for **systems you own or have explicit permission to assess**. It provides transparent checks and reports; it does not exploit systems, deploy malware, steal credentials, evade detection, or retaliate against other devices.

## Features

- **Local audit** — basic host, OS, user, and security-configuration checks.
- **TCP port check** — conservative checks against a target you explicitly specify.
- **HTTP security headers** — inspect common browser security headers.
- **TLS certificate check** — inspect certificate validity and expiry.
- **File integrity** — calculate SHA-256 hashes.
- **Log review** — flag common authentication and privilege-related events in local log files.
- **Password strength estimate** — evaluate a password locally without transmitting or saving it.

## Requirements

- Python 3.10 or newer
- Linux recommended; some checks are platform-dependent
- No third-party Python packages required

## Install

Clone the repository, enter its directory, and install in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows, activate the environment with `.venv\\Scripts\\activate`.

## Usage

```bash
sentinelkit --help
sentinelkit audit
sentinelkit hash ./important-file
sentinelkit headers https://example.com
sentinelkit tls example.com
sentinelkit ports 192.168.1.10 --ports 22,80,443
sentinelkit logs /var/log/auth.log
sentinelkit password-check
```

Port checks are limited to the explicit host and port list supplied by the operator. Only test devices and networks you own or are authorized to assess. Avoid scanning public or shared networks without written permission.

The password checker prompts locally using hidden input. Do not paste passwords into chat, issue trackers, or command-line arguments.

## Project structure

```text
src/sentinelkit/
  __init__.py
  cli.py
tests/
  test_core.py
```

## Safety

- No exploit execution or payload delivery.
- No malware creation, persistence, credential theft, or covert collection.
- No automatic scanning of public IP ranges.
- Network checks require an explicit target.
- Log review reads only the file path supplied by the operator.
- Results are informational and are not a substitute for a professional security assessment.

## Roadmap

Planned defensive additions include configuration baselines, DNS/TLS diagnostics, local process review, structured JSON reports, and optional integrations with established open-source scanners. Each module will have documentation and tests before release.

## Contributing

Feel free to contribute, improve existing tools, add tests, fix bugs, and adapt SentinelKit to your needs. Please read the safety guidelines above and submit changes with clear documentation.

## License

MIT License. See [LICENSE](LICENSE).
