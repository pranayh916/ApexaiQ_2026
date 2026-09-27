# Docker Demo Site

A tiny Python (Flask) website, containerized with Docker.

## Files
- `app.py` — Flask app (routes: `/` and `/health`)
- `templates/index.html` — homepage template
- `requirements.txt` — Python dependencies
- `Dockerfile` — container build instructions
- `.dockerignore` — files excluded from the image

## Run locally (without Docker)
```bash
pip install -r requirements.txt
python app.py
```
Visit http://localhost:5000

## Run with Docker

1. Build the image:
   ```bash
   docker build -t docker-demo-site .
   ```

2. Run the container:
   ```bash
   docker run -d -p 5000:5000 --name demo-site docker-demo-site
   ```

3. Visit http://localhost:5000 in your browser.

4. Check the health endpoint:
   ```bash
   curl http://localhost:5000/health
   ```

5. Stop and remove the container:
   ```bash
   docker stop demo-site
   docker rm demo-site
   ```
