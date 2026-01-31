ARG VERSION=latest
FROM opsdroid/opsdroid:${VERSION}

# Volvemos a root solo para preparar el filesystem
USER root

RUN pip install --no-cache-dir ollama redis aioredis

# Directorios que Opsdroid necesita en runtime
RUN mkdir -p \
    /home/opsdroid/.local/share/opsdroid/site-packages \
    /home/opsdroid/.local/share/opsdroid/opsdroid_modules \
    /var/tmp \
 && chown -R opsdroid:opsdroid /home/opsdroid /var/tmp

# Volvemos al usuario no-root (best practice)
USER opsdroid
