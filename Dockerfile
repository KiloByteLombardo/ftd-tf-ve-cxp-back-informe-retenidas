FROM python:3.11-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar requirements.txt
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación
COPY src/ ./src/

# Agregar src al PYTHONPATH para que los imports funcionen
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Exponer el puerto 8750
EXPOSE 8750

# Variable de entorno para el puerto
ENV PORT=8750

# Comando para ejecutar la aplicación
# Timeout aumentado a 900s (15 min) para soportar búsquedas de Drive con muchas filas
CMD ["gunicorn", "--bind", "0.0.0.0:8750", "--workers", "2", "--timeout", "900", "--graceful-timeout", "900", "--chdir", "/app/src", "api:app"]

