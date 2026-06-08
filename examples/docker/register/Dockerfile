# Development WebAuthn registration server (examples/register/register.py).
#
# Verifies the credential produced by the browser's
# navigator.credentials.create() with python-fido2 and writes it to Redis in
# the format the NGINX module reads. For production registration use the
# bundled CLI auth-webauthn-admin instead.
FROM python:3.12-slim

WORKDIR /app

COPY register/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY register/ ./

# Listen on all interfaces inside the container so nginx can proxy to it.
ENV WEBAUTHN_BIND_HOST=0.0.0.0

EXPOSE 5000

CMD ["python", "register.py"]
