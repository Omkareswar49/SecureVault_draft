FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN chmod +x start.sh
EXPOSE 2222
CMD ["./start.sh"] 