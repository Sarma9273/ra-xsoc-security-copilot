# GitHub-Only Deployment

## Public runtime

GitHub Pages is static hosting, so it is not used as a 24/7 Python server. The public RA-XSOC-X demonstration runs its deterministic demo engine in the browser when `VITE_API_BASE_URL` is not configured.

The full Python/FastAPI research engine remains in the repository for local experiments, reproducible evaluation, and future private/institutional deployment.

## Continuous deployment

`.github/workflows/ci.yml` validates the frontend and lightweight Python suite.

`.github/workflows/deploy-frontend.yml` builds and publishes the frontend to GitHub Pages after pushes to `master`.

In GitHub: **Settings → Pages → Build and deployment → GitHub Actions**.

The Vite base path is `/ra-xsoc-security-copilot/`.

## Public safety boundary

The public browser demo uses synthetic/demo scenarios. It does not execute arbitrary commands, access private SOC systems, or expose credentials. Real SIEM/EDR/PCAP integrations belong to the Python engine and private/local deployments.
