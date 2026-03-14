# sing-box Android remote profile

This repository generates a public sing-box JSON profile for Android from these whitelist sources:

- `zieng2/wl` (`vless_lite.txt`)
- `igareck/vpn-configs-for-russia` (`WHITE-CIDR-RU-checked.txt`)
- `AvenCores/goida-vpn-configs` (`githubmirror/26.txt`)
- optional reserve: `WHITE-CIDR-RU-all.txt`

## How it works

GitHub Actions runs every 30 minutes and rebuilds:

- `dist/sing-box-android-whitelist.json`
- `dist/metadata.json`

Use the raw URL of `dist/sing-box-android-whitelist.json` as a **Remote Profile** in sing-box for Android.

Example raw URL:

`https://raw.githubusercontent.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>/main/dist/sing-box-android-whitelist.json`

## Change parameters

Main tunables are in `generate_config.py`:

- per-source node limits
- `--interval` for `urltest`
- `--tolerance` for `urltest`
- whether to include reserve `WHITE-CIDR-RU-all.txt`

Local test:

```bash
python generate_config.py --output dist/sing-box-android-whitelist.json
```
