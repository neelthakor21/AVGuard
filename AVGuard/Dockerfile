# Use an official Python runtime as a parent image
FROM python:3.9

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /multiav_d

# Copy the current directory contents into the container at /code
COPY . /multiav_d/

# Install any needed packages specified in requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

# Expose port 8000 to the outside world
EXPOSE 8000

# Run Django's development server when the container launches
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
