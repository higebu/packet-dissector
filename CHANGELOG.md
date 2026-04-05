## [0.2.2] - 2026-04-05

### 🚀 Features

- *(ci)* Add error threshold after 30 samples in bencher benchmarks
- *(icmpv6)* Parse invoking packet in type 1/3
- *(icmp)* Parse transport ports in invoking packet

### 🐛 Bug Fixes

- *(renovate)* Upgrade to config:best-practices and fix semanticCommits preset

### ⚙️ Miscellaneous Tasks

- Remove redundant renovate config
- Add conventionalCommits preset to renovate
## [0.2.1] - 2026-04-02

### 🚀 Features

- *(core)* Add DissectBuffer::clear_into for lifetime rebinding

### ⚙️ Miscellaneous Tasks

- *(release)* V0.2.1
## [0.2.0] - 2026-04-01

### 🚀 Features

- *(diameter)* Add 3GPP Gx, Rx, Cx/Dx, Sh interface support

### 🐛 Bug Fixes

- Replace find().is_none() with !any() in dns_test.rs

### 🧪 Testing

- *(dhcpv6)* Add comprehensive unit tests to improve coverage from 18% to 99%

### ⚙️ Miscellaneous Tasks

- Fix codecov-action
- Update AGENTS.md
- Update taplo.toml
- Add publish.yml
- Fix benchmarks.yml
- Update justfile
- *(release)* V0.2.0
## [0.1.0] - 2026-03-31

### ⚙️ Miscellaneous Tasks

- Initial commit
- *(release)* V0.1.0
