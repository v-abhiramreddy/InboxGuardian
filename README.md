# capstone-Agent

## Deployment to Google Cloud Run

This project is prepared to deploy its Streamlit dashboard to Google Cloud Run. Note that this deployment serves a static dashboard based on `results.json`, which must be generated locally before deployment. The deployed container does not fetch live Gmail data on the fly.

### Prerequisites

1. Ensure you have the [Google Cloud CLI (`gcloud`)](https://cloud.google.com/sdk/docs/install) installed and authenticated.
2. Ensure you have generated `results.json` locally by running the full pipeline (e.g. `python main.py`).

### Deployment Commands

Run these exact commands from the root of the project:

```bash
# 1. One-time: create an Artifact Registry repo
gcloud artifacts repositories create capstone-repo --repository-format=docker --location=us-central1

# 2. Build and tag the image
gcloud builds submit --tag us-central1-docker.pkg.dev/YOUR_PROJECT_ID/capstone-repo/capstone-dashboard

# 3. Deploy to Cloud Run
gcloud run deploy capstone-dashboard \
  --image us-central1-docker.pkg.dev/YOUR_PROJECT_ID/capstone-repo/capstone-dashboard \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```
*(Make sure to replace `YOUR_PROJECT_ID` with your actual Google Cloud Project ID).*