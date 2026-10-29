FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY models/ ./models/
COPY api.py .
EXPOSE 8501 8000
# Streamlit prototype (default); run API with: docker run -p 8000:8000 <img> uvicorn api:app --host 0.0.0.0 --port 8000
CMD ["streamlit", "run", "app/app.py", "--server.address=0.0.0.0"]
