<div align="center"><img src="icon/icon_v2_universal.png" alt ="Hacker-Scoper icon"></div>
<br>
<p align="center">
  <a href="https://github.com/ItsIgnacioPortal/hacker-scoper/actions/workflows/gorelease.yml"><img src="https://github.com/ItsIgnacioPortal/Hacker-Scoper/actions/workflows/gorelease.yml/badge.svg?event=push"></a>
  <a href="https://go.dev"><img alt="Golang icon" src="https://img.shields.io/badge/Built_with-GoLang-00acd7?logo=go"></a>
  <a href="https://github.com/ItsIgnacioPortal/Hacker-Scoper/releases"><img alt="Link to the latest version" src="https://img.shields.io/github/v/release/itsignacioportal/hacker-scoper"></a>
  <a href="LICENSE.md"><img alt="Badge depicting the proyect license, the aGPLv3" src="https://img.shields.io/badge/License-aGPLv3-663366?logo=GNU"></a>
  <a href="https://www.bestpractices.dev/projects/10594"><img alt="OpenSSF best practices badge." src="https://www.bestpractices.dev/projects/10594/badge"></a> 
</p>


---

Hacker-Scoper is a CLI tool programmed in GoLang designed to assist cybersecurity professionals in bug bounty programs. Given a mixed list of targets (URLs/IPs), it can quickly filter them to match the bug-bounty program's scope. The scope can be supplied manually, or it can also be detected automatically by just giving hacker-scoper the name of the targeted company.

This project is developed and maintained by [ItsIgnacioPortal](https://github.com/ItsIgnacioPortal).

## 🌟 Features

- **Automatic scope detection**: Hacker-Scoper maintains an automatically-updated cached database of public program scopes. This means you don't need to manually specify the program scope unless the bug bounty program is private. You just need to supply the company name (`-c company-name-here`).

- **Easy customization**: You can load the scope of any private program into files named `.inscope` for inscope assets, and `.noscope` for out-of-scope assets.

- **Match any asset**: Hacker-Scoper works with IPv4, IPv6, and any URL format (including URLs with non-conventional schemes, like `sql://` or `redis://`).

- **Wildcard support**: Hacker-Scoper supports wildcards in any part of your scope, allowing you to use filters like `amzn*.example.com` and `dev.*.example.com`.

- **CIDR Range support**: You can use CIDR ranges in your scopes to filter IP addresses, for example: `10.49.20.0/24` for IPv4 and `2001:DB8::/32` for IPv6.

- **Automation friendly**: Use the `-ch`/`--chain-mode` argument to disable the fancy text decorations and output only the in-scope assets. Hacker-scoper also supports input from stdin.

- **Compatible**: Hacker-Scoper is compatible with Windows, Linux, MacOS and Android in all architectures.

- **Flexible**: For any companies with vaguely defined scopes, you can enable or disable scope wildcard/CIDR parsing using the command-line argument `-e`/`--explicit-level`.

- **Misconfiguration detection**: Using TLD-Based detection, hacker-scoper can automatically detect misconfigurations in bug-bounty program scopes. For example: Sometimes bug bounty programs set APK package names such as `com.my.businness.gatewayportal` as `web_application` resources instead of as `android_application` resources in their program scope, causing trouble for anyone using automatic tools. Hacker-Scoper automatically detects these errors and notifies the user.

## 📦 Installation

**Using Chocolatey**

```
choco install hacker-scoper
```

**Using go install**

```
go install github.com/ItsIgnacioPortal/hacker-scoper
```

**From the releases page**

Download a pre-built binary from [the releases page](https://github.com/ItsIgnacioPortal/hacker-scoper/releases)

<br>

## 🎥 Demos

### Demo with company lookup
[![asciicast](https://asciinema.org/a/WMeGitIu0VEjaFQrbv45fjhJG.svg)](https://asciinema.org/a/WMeGitIu0VEjaFQrbv45fjhJG)
<br>
<br>
<br>
<br>

### Demo with custom scopes file
[![asciicast](https://asciinema.org/a/SWtH3kLbEOmyPzrGFQe9ic9BB.svg)](https://asciinema.org/a/SWtH3kLbEOmyPzrGFQe9ic9BB)

## 🏭 Company scope matching
- **Q: How does the "company" scope matching actually work?**
- A: It works by looking for company-name matches in a cached copy of the [firebounty](https://firebounty.com/) database. The company name that you specify will be lowercase'd, and then the tool will check if any company name in the database contains that string. Once it finds a name match, it will filter your supplied targets according to the scopes that firebounty detected for that company. You can test how this would perform by just searching some name in [the firebounty website](https://firebounty.com/).

## 🤔 Usage
Usage: hacker-scoper --file /path/to/targets [--company company | --inscope-file /path/to/inscopes [--outofscope-file /path/to/outofscopes]] [--explicit-level INT] [--chain-mode] [--database /path/to/firebounty.json] [--include-unsure] [--output /path/to/outputfile] [--hostnames-only]

### Usage examples:
- Example: Cat a file, and lookup scopes on firebounty    
  `cat recon-targets.txt | hacker-scoper -c google`

- Example: Cat a file, and use the .inscope & .noscope files    
  `cat recon-targets.txt | hacker-scoper`

- Example: Manually pick a file, lookup scopes on firebounty, and set explicit-level    
  `hacker-scoper -f recon-targets.txt -c google -e 2`

- Example: Manually pick a file, use custom scopes and out-of-scope files, and set explicit-level    
  `hacker-scoper -f recon-targets.txt -ins inscope -oos noscope.txt -e 2`

**Usage notes:** If no company and no inscope file are specified, hacker-scoper will look for ".inscope" and ".noscope" files in the current or in parent directories.

### Table of all possible arguments:
| Short | Long | Description |
|-------|------|-------------|
| -c | --company |  Specify the company name to lookup. |
| -f | --file |  Path to your file containing URLs/domains/IPs |
| -ins | --inscope-file |  Path to a custom plaintext file containing scopes |
| -oos | --outofscope-file |  Path to a custom plaintext file containing scopes exclusions |
| -e | --explicit-level int |  How explicit we expect the scopes to be:    <br> 1 (default): Include subdomains in the scope even if there's not a wildcard in the scope    <br> 2: Include subdomains in the scope only if there's a wildcard in the scope    <br> 3: Include subdomains/IPs in the scope only if they are explicitly within the scope. CIDR ranges and wildcards are disabled. |
| -ch | --chain-mode |  In "chain-mode" we only output the important information. No decorations. Default: false |
| --database |  | Custom path to the cached firebounty database |
| -iu | --include-unsure |  Include "unsure" URLs in the output. An unsure URL is a URL that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program. |
| -o | --output |  Save the inscope urls to a file |
| -ho | --hostnames-only |  Output only hostnames instead of the full URLs |
| --version |  | Show the installed version |
|_______________|___________________| _____________________________________ |

list example:
```javascript
example.com
dev.example.com
1.dev.example.com
2.dev.example.com
ads.example.com
192.168.1.10
192.168.2.10
192.168.2.8
2001:db8:0000:0000:0000:0000:0000:0001
2001:db8:0000:0000:0000:0000:0000:0002
2001:db8::3
2001:db9:0000:0000:0000:0000:0000:0004
2001:db9::5
```

Custom .inscope file example:
```javascript
*.example.com
*.sub.domain.example.com
amzn*.domain.example.com
192.168.2.10
192.168.1.0/24
FE80:0000:0000:0000:0202:B3FF:FE1E:8329
FE80::0202:B3FF:FE1E:8329
2001:DB8::/32
```

Custom .noscope file example:
```javascript
community.example.com
thirdparty.example.com
*.thirdparty.example.com
dev.*.example.com
192.168.2.8
FE80::0202:B3FF:FE1E:8330
```

## :heart: Special thank you
This project was inspired by the [yeswehack_vdp_finder](https://github.com/yeswehack/yeswehack_vdp_finder)

## 📄 License
All of the code on this repository is licensed under the *GNU Affero General Public License v3*. A copy can be seen as `LICENSE` on this repository.

The library `golang.org/x/net/publicsuffix`, used within this project is licensed with [BSD-3-Clause](https://pkg.go.dev/golang.org/x/net/publicsuffix?tab=licenses).
