FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN python -m pip install --upgrade pip &&     pip install -e "./packages/ra_xsoc_engine[ai]" &&     pip install -e "./packages/ra_xsoc_api"
EXPOSE 8000
CMD ["uvicorn","ra_xsoc_api.main:app","--host","0.0.0.0","--port","8000"]
