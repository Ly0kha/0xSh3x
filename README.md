# 🐉 0xSh3x

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Ly0kha/0xsh3x)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL-orange.svg)](#)
[![Kali](https://img.shields.io/badge/Kali%20Linux-Ready-red.svg)](#)

Automate reconnaissance. Stop running 10 different tools manually. Let 0xSh3x handle it.

## ⚙️ Requirements

- 🐧 Linux or WSL
- 💻 Bash 5.0+
- 📦 curl, jq, wget, git
- 🔨 Go 1.19+ (for Go tools)

## 📥 Install

```bash
git clone https://github.com/Ly0kha/0xsh3x.git
cd 0xsh3x
chmod +x 0xsh3x.sh
./0xsh3x.sh --install-deps
```

## 🚀 Usage

```bash
# Basic scan
./0xsh3x.sh target.com

# With Tor (stealth)
./0xsh3x.sh target.com --tor

# Single domain only
./0xsh3x.sh target.com --single

# Custom scope
./0xsh3x.sh --scope scope.txt --tor
```

## ⚡ What It Automates

- 🌐 Subdomain enumeration (6 sources in parallel)
- 🔍 DNS validation and harvesting
- 🏄 HTTP probing (automatically find live hosts)
- 🔧 Technology fingerprinting
- 📱 URL discovery (Wayback + crawling + active)
- 📄 JavaScript analysis and secret extraction
- 🔬 Port scanning
- 📂 Directory discovery
- 🛡️ Security headers audit
- 🚨 WAF/CDN detection
- ↩️ Open redirect hunting
- 🔐 Exposed file discovery (.env, .git, credentials)

## 📊 Output

Results saved to `0xsh3x_results/`:

```
├── 01-subdomains/       (all found domains)
├── 02-hosts/            (live hosts + analysis)
├── 03-directories/      (discovered paths)
├── 04-javascript/       (JS files + secrets)
├── 05-urls/             (all URLs found)
├── 06-security/         (headers, WAF, tech)
├── 07-ports/            (open ports)
└── 08-reports/          (final report)
```

## ⏱️ Time Saved

- ❌ **Manual recon:** 30-40 hours per target
- ✅ **With 0xSh3x:** 1-2 hours per target
- 🚀 **Automation gain:** 95% faster

## ✨ Features

- 📋 12-phase workflow
- ⚡ Parallel execution
- ⏸️ Resume on interrupt
- 🧅 Tor/proxy support
- 📋 Scope enforcement
- ⏪️ Smart rate limiting
- Infrastructure mapping
- Secrets detection

## Config

Most features work out of the box. If you want to customize:

```bash
CONNECTION_METHOD="tor"        # tor, proxy, direct
SCOPE_TYPE="wildcard"          # wildcard, single, custom
OUTPUT_DIR="./0xsh3x_results"
```

