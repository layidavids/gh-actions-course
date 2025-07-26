###############################
# STAGE 1: Build tailwind CSS #
###############################
FROM node:22-alpine AS tailwind-builder

# Set working directory
WORKDIR /app

# Copy package.json
COPY theme/ ./theme/

# Set working directory to static_src
WORKDIR /app/theme/static_src

# Install Tailwind and dev dependencies
RUN npm install

# Build Tailwind CSS
RUN npm run build

####################################
# STAGE 2: Build Django Cyph3r app #
####################################

FROM python:3.12-slim

# Set Environment Variables to prevent Python from writing .pyc files and to ensure output is sent straight to terminal
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1


# Set working directory
WORKDIR /cyph3r

# Install system dependencies including Redis
RUN apt-get update && apt-get install -y redis-server gnupg libmagic1 && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Django Cyph3r app code
COPY . .

# Copy the built Tailwind CSS from the first stage
COPY --from=tailwind-builder /app/theme/static/css/dist/ ./theme/static/css/dist/

# Set environment variable for Django Secret Key
ENV DJANGO_DEV_SECRET_KEY="$(python3 -c 'import django.utils.crypto; print(django.utils.crypto.get_random_string(50, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-="))')"
ENV DJANGO_ALLOWED_HOSTS=*

# Run Django DB migrations
RUN python manage.py migrate

# Expose the port
EXPOSE 8080

# Start the Django Server and Redis server
CMD ["sh", "-c", "redis-server --daemonize yes && python manage.py runserver 0.0.0.0:8080"]