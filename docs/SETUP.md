# JASUSI — Before You Start (checklist)

## 1. Install
- [ ] Python 3.11+ · Node.js 20+ · Git · Docker Desktop
- [ ] Claude Code (`npm install -g @anthropic-ai/claude-code`), then run `claude` inside the `jasusi/` folder
- [ ] VS Code (optional) with Python + ESLint extensions

## 2. Accounts & keys (free tiers)
- [ ] GitHub repo: `jasusi` (private until the defence)
- [ ] Hugging Face account (model downloads, optional model hosting)
- [ ] Google Colab (free GPU for fine-tuning)
- [ ] VirusTotal API key
- [ ] Google Safe Browsing API key (Google Cloud console)
- [ ] PhishTank / OpenPhish feed access
- [ ] Put all keys in `.env` (copy from `.env.example`). **Never commit `.env`.**

## 3. Admin
- [ ] Supervisor approval of the topic + proposal
- [ ] Ethics clearance if collecting real messages / running user tests
- [ ] Consent form text ready
- [ ] Start collecting scam messages NOW (data is the slowest part)

## 4. First Claude Code session — suggested prompt
```
Read CLAUDE.md and everything in docs/. Summarise the project in 5 bullets,
then start Milestone M0 from docs/ROADMAP.md. Confirm your plan before writing code.
```
