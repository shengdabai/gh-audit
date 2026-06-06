# 🛡️ gh-audit

[![Last commit](https://img.shields.io/github/last-commit/shengdabai/gh-audit)](https://github.com/shengdabai/gh-audit/commits)
[![Stars](https://img.shields.io/github/stars/shengdabai/gh-audit?style=social)](https://github.com/shengdabai/gh-audit/stargazers)
[![Follow @shengdabai](https://img.shields.io/github/followers/shengdabai?style=social)](https://github.com/shengdabai)

**English | [中文](#中文)**

> One command to audit any GitHub repo — or a whole org — for leaked secrets, exposed PII, vulnerable dependencies, IaC misconfigurations, and missing security governance.

`gh-audit` is a single-binary Python CLI that clones a repository, runs six independent detection modules, redacts every piece of sensitive evidence before it ever touches your terminal, and writes the results as terminal output, JSON, or a self-contained HTML report. It works out of the box with zero external tools, and gets sharper when you bolt on industry scanners like gitleaks, semgrep, or trivy.

## Why

Security tooling is usually a pile of separate CLIs, each with its own output format, its own config, and its own way of leaking the very secrets it just found into your scrollback. `gh-audit` collapses that into one consistent, redaction-first workflow:

- **Audit by name, not by checkout.** Point it at `owner/repo` or `--org myorg` and it handles cloning and cleanup for you.
- **Safe by default.** Every secret, ID number, phone number, and email is redacted before it's printed, logged, or saved.
- **Zero-dependency floor, scanner-enhanced ceiling.** Built-in detectors always run; optional tools deepen coverage when present.
- **Diff-aware.** `--diff` reports only what's *new* since the last scan, so re-audits don't drown you in known findings.

## ✨ Checks

| Module | Built-in | Enhanced with |
|--------|----------|---------------|
| **secrets** | ✓ regex (AWS, GitHub, OpenAI, Stripe, private keys, generic API keys & passwords) + Shannon-entropy detection | gitleaks, trufflehog |
| **pii** | ✓ CN phone, CN national ID, bank card (Luhn-validated), email | presidio |
| **governance** | ✓ branch-protection, `SECURITY.md`, `CODEOWNERS` checks via GitHub API | — |
| **sca** | ✓ dependency vulns via OSV.dev API (`requirements*.txt`, `package-lock.json`) | osv-scanner |
| **sast** | — (requires a scanner) | semgrep, bandit |
| **iac** | — (requires a scanner) | trivy, checkov |

Every finding is normalized into a common schema with a **severity** (critical → info), a **confidence** level (confirmed / likely / possible), a redacted evidence snippet, a fix recommendation, and **standards mappings** (CWE-798, OWASP-A02, GDPR-Art5, SLSA-L1, OpenSSF-Scorecard).

## 🔑 Features

- **Six detection modules** — run all of them or a subset with `--modules secrets,pii`.
- **Redaction-first** — sensitive values are masked everywhere they appear.
- **Three output formats** — `terminal`, `json`, and a self-contained `html` report.
- **Severity filtering** — `--min-severity high` to cut the noise.
- **Diff mode** — `--diff` surfaces only findings new since the previous scan.
- **Deduplication** — overlapping detectors won't report the same secret twice.
- **Suppressions** — silence a known false-positive by its content fingerprint, with an expiry.
- **Scan history** — every JSON report is kept; `gh-audit history owner/repo` shows the trend.
- **Org-wide scanning** — `--org` discovers and audits every repo in an organization.
- **`doctor`** — one command tells you which optional tools are installed and whether your token is valid.

## 🧱 Tech stack

Python 3.11+ · [click](https://click.palletsprojects.com/) (CLI) · [rich](https://rich.readthedocs.io/) (terminal UI) · [PyGithub](https://pygithub.readthedocs.io/) (GitHub API) · [GitPython](https://gitpython.readthedocs.io/) (cloning) · [requests](https://requests.readthedocs.io/) (OSV.dev) · [presidio-analyzer](https://microsoft.github.io/presidio/) (PII) · packaged with [hatchling](https://hatch.pypa.io/).

## 🚀 Install & run

```bash
pipx install gh-audit
# or
pip install gh-audit
```

```bash
export GITHUB_TOKEN=ghp_yourtoken

# Scan one repo
gh-audit scan owner/repo

# Scan a whole org, write HTML + JSON reports
gh-audit scan --org myorg --output terminal,json,html

# Only secrets + PII, high severity and up, new findings only
gh-audit scan owner/repo --modules secrets,pii --min-severity high --diff

# Check which optional tools are installed + token status
gh-audit doctor
```

Add optional scanners for deeper coverage:

```bash
pip install semgrep bandit        # SAST
brew install osv-scanner trivy    # SCA + IaC
```

### CLI reference

```bash
gh-audit scan owner/repo [--branch main] [--modules secrets,pii] \
                         [--output terminal,json,html] [--min-severity high] [--diff]
gh-audit scan --org myorg
gh-audit doctor
gh-audit history owner/repo
gh-audit suppress <fingerprint> --reason "false positive" --expires 30d
gh-audit config set token ghp_xxx
```

## 📖 Example output

```
Scanning: owner/repo
  ✓ secrets: 2 findings
  ✓ pii: 1 findings
  ✓ governance: 3 findings
  ○ sast — tool not found
JSON → ~/.gh-audit/results/owner_repo/20260606_120000.json
```

`gh-audit history owner/repo` then prints a per-scan severity breakdown (`2c 1h 0m 3l`) so you can watch findings drop over time.

## 🗺️ Status

Early but functional (v0.1) — the six modules, redaction, dedup, diff, suppressions, and all three reporters work today and are covered by a test suite under `tests/`. Built in public; feedback and issues welcome.

## 🤝 Connect

Built by **Tony (Sheng)** — a Chinese-language teacher (6000+ students) building AI + Chinese-teaching tools in the open.

If `gh-audit` is useful to you, please **⭐ Star this repo** and **[Follow @shengdabai](https://github.com/shengdabai)** to follow along.

More tools in the same spirit:

- [Small-yet-smart-programs](https://github.com/shengdabai/Small-yet-smart-programs) — a collection of small, sharp utilities.
- [claude-code-config](https://github.com/shengdabai/claude-code-config) — a battle-tested Claude Code setup.
- [everything-claude-code](https://github.com/shengdabai/everything-claude-code) — everything for getting the most out of Claude Code.

## License

No license has been declared yet. Until one is added, all rights are reserved by the author. Open an issue if you'd like to use this in your own project.

---

<a name="中文"></a>

# 🛡️ gh-audit（中文）

[![Last commit](https://img.shields.io/github/last-commit/shengdabai/gh-audit)](https://github.com/shengdabai/gh-audit/commits)
[![Stars](https://img.shields.io/github/stars/shengdabai/gh-audit?style=social)](https://github.com/shengdabai/gh-audit/stargazers)
[![Follow @shengdabai](https://img.shields.io/github/followers/shengdabai?style=social)](https://github.com/shengdabai)

**[English](#️-gh-audit) | 中文**

> 一条命令，审计任意 GitHub 仓库（或整个组织）——泄露的密钥、暴露的个人信息（PII）、有漏洞的依赖、IaC 错误配置，以及缺失的安全治理。

`gh-audit` 是一个单一的 Python 命令行工具：它会克隆仓库、运行六个独立的检测模块、在任何敏感证据进入终端之前先做脱敏处理，并把结果输出为终端文本、JSON 或一个自包含的 HTML 报告。开箱即用、零外部依赖；当你额外安装 gitleaks、semgrep、trivy 等业界扫描器后，覆盖面会进一步加深。

## 为什么用它

安全工具往往是一堆各自为政的 CLI——各有各的输出格式、各有各的配置，还各有各把刚扫出来的密钥原样打进你的终端历史的方式。`gh-audit` 把它们收敛成一套统一、脱敏优先的工作流：

- **按名字审计，无需手动 checkout。** 直接指向 `owner/repo` 或 `--org myorg`，克隆与清理都交给它。
- **默认安全。** 每一个密钥、身份证号、手机号、邮箱在打印、记录或保存之前都会先脱敏。
- **零依赖底线，扫描器加持上限。** 内置检测器始终运行；安装可选工具后覆盖更深。
- **支持差异比对。** `--diff` 只报告自上次扫描以来「新增」的问题，复扫时不被旧结果淹没。

## ✨ 检测项

| 模块 | 内置 | 可增强 |
|------|------|--------|
| **secrets** | ✓ 正则（AWS、GitHub、OpenAI、Stripe、私钥、通用 API key 与密码）+ 香农熵检测 | gitleaks、trufflehog |
| **pii** | ✓ 中国手机号、身份证号、银行卡（Luhn 校验）、邮箱 | presidio |
| **governance** | ✓ 通过 GitHub API 检查分支保护、`SECURITY.md`、`CODEOWNERS` | — |
| **sca** | ✓ 通过 OSV.dev API 检测依赖漏洞（`requirements*.txt`、`package-lock.json`） | osv-scanner |
| **sast** | —（需安装扫描器） | semgrep、bandit |
| **iac** | —（需安装扫描器） | trivy、checkov |

每条发现都会被规范化为统一结构：**严重级别**（critical → info）、**置信度**（confirmed / likely / possible）、脱敏后的证据片段、修复建议，以及**标准映射**（CWE-798、OWASP-A02、GDPR-Art5、SLSA-L1、OpenSSF-Scorecard）。

## 🔑 特性

- **六个检测模块** — 全跑，或用 `--modules secrets,pii` 只跑子集。
- **脱敏优先** — 敏感值在任何出现的地方都会被遮蔽。
- **三种输出格式** — `terminal`、`json`，以及自包含的 `html` 报告。
- **严重级别过滤** — `--min-severity high` 降噪。
- **差异模式** — `--diff` 只显示自上次扫描以来的新增问题。
- **去重** — 不同检测器命中同一密钥时不会重复报告。
- **抑制（suppressions）** — 用内容指纹屏蔽已知误报，并设置过期时间。
- **扫描历史** — 每次 JSON 报告都会保留；`gh-audit history owner/repo` 查看趋势。
- **组织级扫描** — `--org` 自动发现并审计组织内的所有仓库。
- **`doctor`** — 一条命令告诉你哪些可选工具已安装、token 是否有效。

## 🧱 技术栈

Python 3.11+ · [click](https://click.palletsprojects.com/)（命令行）· [rich](https://rich.readthedocs.io/)（终端 UI）· [PyGithub](https://pygithub.readthedocs.io/)（GitHub API）· [GitPython](https://gitpython.readthedocs.io/)（克隆）· [requests](https://requests.readthedocs.io/)（OSV.dev）· [presidio-analyzer](https://microsoft.github.io/presidio/)（PII）· 使用 [hatchling](https://hatch.pypa.io/) 打包。

## 🚀 安装与运行

```bash
pipx install gh-audit
# 或
pip install gh-audit
```

```bash
export GITHUB_TOKEN=ghp_yourtoken

# 扫描单个仓库
gh-audit scan owner/repo

# 扫描整个组织，输出 HTML + JSON 报告
gh-audit scan --org myorg --output terminal,json,html

# 只扫 secrets + PII，仅 high 及以上，且只看新增
gh-audit scan owner/repo --modules secrets,pii --min-severity high --diff

# 检查可选工具安装情况 + token 状态
gh-audit doctor
```

安装可选扫描器以获得更深覆盖：

```bash
pip install semgrep bandit        # SAST
brew install osv-scanner trivy    # SCA + IaC
```

### 命令参考

```bash
gh-audit scan owner/repo [--branch main] [--modules secrets,pii] \
                         [--output terminal,json,html] [--min-severity high] [--diff]
gh-audit scan --org myorg
gh-audit doctor
gh-audit history owner/repo
gh-audit suppress <fingerprint> --reason "false positive" --expires 30d
gh-audit config set token ghp_xxx
```

## 📖 输出示例

```
Scanning: owner/repo
  ✓ secrets: 2 findings
  ✓ pii: 1 findings
  ✓ governance: 3 findings
  ○ sast — tool not found
JSON → ~/.gh-audit/results/owner_repo/20260606_120000.json
```

随后 `gh-audit history owner/repo` 会打印每次扫描的严重级别分布（`2c 1h 0m 3l`），让你看到问题随时间下降的趋势。

## 🗺️ 项目状态

早期但可用（v0.1）——六个模块、脱敏、去重、差异、抑制以及三种报告器现在都能工作，并由 `tests/` 下的测试套件覆盖。Build in public，欢迎反馈和提 issue。

## 🤝 联系

由 **Tony (Sheng)** 开发——一名中文老师（6000+ 学员），在公开场合构建 AI + 中文教学工具。

如果 `gh-audit` 对你有用，请 **⭐ Star 本仓库** 并 **[关注 @shengdabai](https://github.com/shengdabai)**，跟进后续更新。

同系列的更多工具：

- [Small-yet-smart-programs](https://github.com/shengdabai/Small-yet-smart-programs) — 一组小而锋利的实用工具。
- [claude-code-config](https://github.com/shengdabai/claude-code-config) — 一套久经实战的 Claude Code 配置。
- [everything-claude-code](https://github.com/shengdabai/everything-claude-code) — 把 Claude Code 用到极致所需的一切。

## 许可证

尚未声明许可证。在添加许可证之前，作者保留所有权利。如需在你自己的项目中使用，请提 issue 联系。
