import os
import sys
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from google.auth import default, load_credentials_from_file
from google.cloud import bigquery, storage
import gspread
from werkzeug.utils import secure_filename
import io
import logging
import venezuela
import emailSend
import requests
import json

app = Flask(__name__)
# Configurar CORS para permitir todos los orígenes
CORS(app, resources={r"/*": {"origins": "*"}})

# Configurar logging para ver las peticiones en tiempo real
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
app.logger.setLevel(logging.INFO)
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)

HEADERS = {
    'Authorization': f'Bearer {os.getenv("GRIST_API_KEY")}',
    'Content-Type': 'application/json'
}

SERVER_URL = os.getenv("GRIST_SERVER_URL")
DOC_ID = os.getenv("GRIST_DOC_ID")
TABLE_ID = os.getenv("GRIST_TABLE_ID")

# Configuración del Google Sheet para emails
EMAIL_SPREADSHEET_ID = os.getenv("EMAIL_SPREADSHEET_ID")
EMAIL_WORKSHEET_NAME = os.getenv("EMAIL_WORKSHEET_NAME", "Sheet1")
EMAIL_WORKSHEET_GID = os.getenv("EMAIL_WORKSHEET_GID")  # GID numérico de la hoja (opcional)

def get_credentials():
    """
    Obtiene credenciales de GCP, primero intenta desde credentials.json,
    si no está disponible, usa ADC (Application Default Credentials).
    
    Returns:
        tuple: (credentials, project_id)
    """
    # Obtener la ruta desde variable de entorno o usar la ruta por defecto
    credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS', '/app/credentials.json')
    
    # Intentar cargar desde credentials.json
    if os.path.exists(credentials_path):
        try:
            print(f"Loading credentials from {credentials_path}")
            sys.stdout.flush()
            credentials, project = load_credentials_from_file(credentials_path)
            return credentials, project
        except Exception as e:
            print(f"Warning: Could not load credentials from {credentials_path}: {str(e)}")
            print("Falling back to Application Default Credentials (ADC)")
            sys.stdout.flush()
    
    # Fallback a ADC
    print("Using Application Default Credentials (ADC)")
    sys.stdout.flush()
    credentials, project = default()
    return credentials, project


def test_bigquery_connection(credentials, project_id: str) -> tuple:
    """
    Prueba la conexión a BigQuery.
    
    Args:
        credentials: Credenciales de GCP
        project_id: ID del proyecto de GCP
    
    Returns:
        tuple: (success, message)
    """
    try:
        bigquery_client = bigquery.Client(credentials=credentials, project=project_id)
        # Intentar listar datasets del proyecto
        datasets = list(bigquery_client.list_datasets())
        return True, f"Successfully connected to BigQuery. Project: {project_id}, Datasets found: {len(datasets)}"
    except Exception as e:
        return False, f"Error connecting to BigQuery: {str(e)}"


def test_storage_connection(credentials, project_id: str) -> tuple:
    """
    Prueba la conexión a Cloud Storage.
    
    Args:
        credentials: Credenciales de GCP
        project_id: ID del proyecto de GCP
    
    Returns:
        tuple: (success, message)
    """
    try:
        storage_client = storage.Client(credentials=credentials, project=project_id)
        # Intentar listar buckets del proyecto
        buckets = list(storage_client.list_buckets())
        return True, f"Successfully connected to Cloud Storage. Project: {project_id}, Buckets found: {len(buckets)}"
    except Exception as e:
        return False, f"Error connecting to Cloud Storage: {str(e)}"


@app.route('/health', methods=['GET'])
def health():
    """
    Endpoint de health check.
    
    Returns:
        JSON con el estado del servicio
    """
    print("=" * 50)
    print("[HEALTH] Endpoint called")
    print(f"[HEALTH] Method: {request.method}")
    print(f"[HEALTH] Service is running")
    print("=" * 50)
    sys.stdout.flush()
    
    return jsonify({
        'status': 'healthy',
        'service': 'vzla-r011-direct-cleaning',
        'message': 'Service is running'
    }), 200


@app.route('/test/bigquery', methods=['GET'])
def test_bigquery_endpoint():
    """
    Endpoint para probar la conexión a BigQuery.
    
    Returns:
        JSON con el resultado de la prueba de conexión
    """
    print("=" * 50)
    print("[TEST BIGQUERY] Endpoint called")
    print(f"[TEST BIGQUERY] Method: {request.method}")
    sys.stdout.flush()
    
    try:
        print("[TEST BIGQUERY] Getting credentials...")
        sys.stdout.flush()
        credentials, project_id = get_credentials()
        
        print(f"[TEST BIGQUERY] Testing connection to project: {project_id}")
        sys.stdout.flush()
        success, message = test_bigquery_connection(credentials, project_id)
        
        print(f"[TEST BIGQUERY] Result: {success} - {message}")
        sys.stdout.flush()
        
        status_code = 200 if success else 500
        return jsonify({
            'success': success,
            'message': message
        }), status_code
    except Exception as e:
        print(f"[TEST BIGQUERY] Error: {str(e)}")
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'message': f'Error testing BigQuery connection: {str(e)}'
        }), 500


@app.route('/test/storage', methods=['GET'])
def test_storage_endpoint():
    """
    Endpoint para probar la conexión a Cloud Storage.
    
    Returns:
        JSON con el resultado de la prueba de conexión
    """
    print("=" * 50)
    print("[TEST STORAGE] Endpoint called")
    print(f"[TEST STORAGE] Method: {request.method}")
    sys.stdout.flush()
    
    try:
        print("[TEST STORAGE] Getting credentials...")
        sys.stdout.flush()
        credentials, project_id = get_credentials()
        
        print(f"[TEST STORAGE] Testing connection to project: {project_id}")
        sys.stdout.flush()
        success, message = test_storage_connection(credentials, project_id)
        
        print(f"[TEST STORAGE] Result: {success} - {message}")
        sys.stdout.flush()
        
        status_code = 200 if success else 500
        return jsonify({
            'success': success,
            'message': message
        }), status_code
    except Exception as e:
        print(f"[TEST STORAGE] Error: {str(e)}")
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'message': f'Error testing Cloud Storage connection: {str(e)}'
        }), 500


@app.route('/process', methods=['POST'])
def process_file():
    """
    Endpoint para procesar un archivo Excel.
    Recibe un archivo Excel como form-data con el campo "file", lo procesa y sube automáticamente a Cloud Storage.
    
    El archivo procesado se sube automáticamente a Cloud Storage usando las variables de entorno:
        - GCS_BUCKET_NAME: Nombre del bucket de Cloud Storage (requerido)
        - GCS_FOLDER_NAME: Carpeta dentro del bucket (opcional, default: 'processed')
    
    Query parameters opcionales:
        - upload_bigquery: Si está presente y es 'true', sube el resultado a BigQuery
        - dataset_id: ID del dataset de BigQuery (requerido si upload_bigquery=true)
        - table_id: ID de la tabla de BigQuery (requerido si upload_bigquery=true)
    
    Returns:
        JSON con la siguiente estructura:
        {
            'success': bool,
            'message': str,
            'filename': str,  # Nombre del archivo original
            'processed_filename': str,  # Nombre del archivo procesado
            'download_url': str,  # URL pública para descargar el archivo desde Cloud Storage
            'uploads': {
                'storage': {
                    'success': bool,
                    'bucket': str,
                    'blob': str,
                    'url': str
                },
                'bigquery': {  # Solo si upload_bigquery=true
                    'success': bool,
                    'dataset': str,
                    'table': str
                }
            }
        }
    """
    print("=" * 50)
    print("[PROCESS] Endpoint called")
    print(f"[PROCESS] Method: {request.method}")
    print(f"[PROCESS] Content-Type: {request.content_type}")
    sys.stdout.flush()
    
    try:
        # Verificar que se haya enviado un archivo
        if 'file' not in request.files:
            print("[PROCESS] Error: No file provided in form-data")
            sys.stdout.flush()
            return jsonify({
                'error': 'No file provided',
                'message': 'Please provide an Excel file in the "file" field as form-data'
            }), 400
        
        file = request.files['file']
        print(f"[PROCESS] File received: {file.filename}")
        sys.stdout.flush()
        
        if file.filename == '':
            print("[PROCESS] Error: Empty filename")
            sys.stdout.flush()
            return jsonify({
                'error': 'No file selected',
                'message': 'Please select a file to upload'
            }), 400
        
        # Verificar que sea un archivo Excel
        if not (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')):
            print(f"[PROCESS] Error: Invalid file type - {file.filename}")
            sys.stdout.flush()
            return jsonify({
                'error': 'Invalid file type',
                'message': 'Please upload an Excel file (.xlsx or .xls)'
            }), 400
        
        # Leer el contenido del archivo
        print(f"[PROCESS] Reading file content...")
        sys.stdout.flush()
        
        # Asegurarse de que el archivo se lea como bytes
        # Resetear el stream al inicio por si acaso
        file.seek(0)
        file_content = file.read()
        
        # Verificar que el contenido sea bytes
        if not isinstance(file_content, bytes):
            file_content = file_content.encode('utf-8') if isinstance(file_content, str) else bytes(file_content)
        
        filename = secure_filename(file.filename)

        # Verificar que el archivo no esté vacío
        if len(file_content) == 0:
            print("[PROCESS] Error: File is empty")
            sys.stdout.flush()
            return jsonify({
                'error': 'Empty file',
                'message': 'The uploaded file is empty'
            }), 400
        
        # Verificar que sea un archivo Excel válido (debe empezar con PK para .xlsx o D0CF para .xls)
        if not (file_content.startswith(b'PK') or file_content.startswith(b'\xd0\xcf')):
            print("[PROCESS] Warning: File might not be a valid Excel file (doesn't start with expected magic bytes)")
            sys.stdout.flush()
            # Continuar de todas formas, podría ser un formato válido
        
        # Obtener credenciales para el procesamiento y los uploads
        credentials, project_id = get_credentials()
        
        # Procesar el archivo y obtener el DataFrame (no solo el contenido Excel)
        print(f"[PROCESS] Processing file: {filename}")
        sys.stdout.flush()
        
        # Primero procesar el archivo para obtener el DataFrame
        import pandas as pd
        header_row = venezuela.detect_headers(file_content)
        if header_row is not None:
            df = pd.read_excel(io.BytesIO(file_content), header=header_row)
        else:
            df = pd.read_excel(io.BytesIO(file_content))
        df.columns = [str(col).strip() for col in df.columns]
        
        # Procesar el DataFrame (sin comentarios todavía)
        df_processed = venezuela.process_dataframe(df, credentials)
        print(f"[PROCESS] DataFrame processed. Shape: {df_processed.shape}")
        sys.stdout.flush()
        
        # Obtener df_old_grist de Grist ANTES de borrar/subir nuevos datos
        print("[PROCESS] Getting old Grist data for comentarios matching...")
        sys.stdout.flush()
        df_old_grist = None
        
        # Verificar si Grist está configurado
        if SERVER_URL and DOC_ID and TABLE_ID:
            try:
                url_records = f'{SERVER_URL}/{DOC_ID}/tables/{TABLE_ID}/records'
                response = requests.get(url_records, headers=HEADERS)
                
                if response.status_code == 200:
                    data_grist_table = response.json()
                    records = data_grist_table.get('records', [])
                    
                    if records:
                        records_data = []
                        for record in records:
                            if 'fields' in record:
                                records_data.append(record['fields'])
                        
                        if records_data:
                            df_old_grist = pd.DataFrame(records_data)
                            print(f"[PROCESS] Retrieved {len(df_old_grist)} rows from old Grist table")
                            sys.stdout.flush()
                        else:
                            print("[PROCESS] No data fields found in Grist records")
                            sys.stdout.flush()
                    else:
                        print("[PROCESS] No records found in Grist table (table is empty)")
                        sys.stdout.flush()
                else:
                    print(f"[PROCESS] Warning: Could not get Grist data: {response.status_code}")
                    sys.stdout.flush()
            except Exception as e:
                print(f"[PROCESS] Warning: Error getting Grist data: {str(e)}")
                sys.stdout.flush()
        else:
            print("[PROCESS] Warning: Grist not configured. Skipping comentarios matching")
            sys.stdout.flush()
        
        # Hacer el pareo de comentarios con df_old_grist
        if df_old_grist is not None and not df_old_grist.empty:
            print("[PROCESS] Matching comentarios from old Grist data...")
            sys.stdout.flush()
            df_processed = add_comentarios_from_grist(df_processed, df_old_grist)
        else:
            # Inicializar columnas vacías si no hay datos antiguos
            df_processed['Comentario'] = ''
            df_processed['Comentario CXP'] = ''
            print("[PROCESS] No old Grist data available. Comentarios columns initialized as empty")
            sys.stdout.flush()
        
        # Agregar columnas adicionales requeridas por BigQuery
        # Estas columnas se agregan después del procesamiento y antes de subir a Grist/BigQuery
        if 'Comentario Operación' not in df_processed.columns:
            df_processed['Comentario Operación'] = ''
            print("[PROCESS] Added 'Comentario Operación' column (empty)")
            sys.stdout.flush()
        
        if 'Fecha Reporte CXP' not in df_processed.columns:
            # Inicializar como fecha vacía (None o NaT)
            df_processed['Fecha Reporte CXP'] = pd.NaT
            print("[PROCESS] Added 'Fecha Reporte CXP' column (empty)")
            sys.stdout.flush()
        
        # Convertir el DataFrame procesado (con comentarios) a Excel
        print("[PROCESS] Converting processed DataFrame to Excel...")
        sys.stdout.flush()
        output = io.BytesIO()
        df_processed.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        processed_content = output.getvalue()
        print(f"[PROCESS] File processed successfully. Output size: {len(processed_content)} bytes")
        sys.stdout.flush()
        
        # Obtener configuración de Cloud Storage desde variables de entorno
        storage_bucket = os.getenv('GCS_BUCKET_NAME')
        storage_folder = os.getenv('GCS_FOLDER_NAME', 'processed')
        
        # Generar nombre del archivo con timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(filename)[0]
        extension = os.path.splitext(filename)[1] or '.xlsx'
        output_filename = f"Informe_R011_{timestamp}{extension}"
        blob_name = f"{storage_folder}/{output_filename}" if storage_folder else output_filename
        
        response_data = {
            'success': True,
            'message': 'File processed successfully',
            'filename': filename,
            'processed_filename': output_filename,
            'download_url': None,
            'uploads': {}
        }
        
        # Subir a Cloud Storage automáticamente
        if storage_bucket:
            print(f"[PROCESS] Uploading to Cloud Storage: gs://{storage_bucket}/{blob_name}")
            sys.stdout.flush()
            success, result = venezuela.upload_to_storage(
                processed_content, credentials, project_id, storage_bucket, blob_name
            )
            if success:
                response_data['download_url'] = result
                response_data['uploads']['storage'] = {
                    'success': True,
                    'bucket': storage_bucket,
                    'blob': blob_name,
                    'url': result
                }
                print(f"[PROCESS] Cloud Storage upload successful. URL: {result}")
                sys.stdout.flush()
            else:
                response_data['uploads']['storage'] = {
                    'success': False,
                    'error': result
                }
                print(f"[PROCESS] Cloud Storage upload failed: {result}")
                sys.stdout.flush()
        else:
            print("[PROCESS] Warning: GCS_BUCKET_NAME not configured. File not uploaded to Cloud Storage")
            sys.stdout.flush()
            response_data['uploads']['storage'] = {
                'success': False,
                'message': 'GCS_BUCKET_NAME environment variable not set'
            }
        
        # Procesar con Grist (borrar datos antiguos, subir nuevos, subir antiguos a BigQuery)
        if SERVER_URL and DOC_ID and TABLE_ID:
            print("[PROCESS] Processing with Grist...")
            sys.stdout.flush()
            
            # Llamar a process_grist con df_old_grist ya obtenido (no necesita obtenerlo de nuevo)
            grist_result = process_grist(df_processed, credentials, project_id, df_old_grist)
            response_data['uploads']['grist'] = grist_result
            print(f"[PROCESS] Grist processing completed. Success: {grist_result['success']}")
            sys.stdout.flush()
        else:
            print("[PROCESS] Grist not configured. Skipping Grist processing")
            sys.stdout.flush()
            response_data['uploads']['grist'] = {
                'success': False,
                'message': 'Grist not configured (missing GRIST_SERVER_URL, GRIST_DOC_ID, or GRIST_TABLE_ID)'
            }
        
        # Obtener parámetros opcionales para BigQuery
        upload_bigquery = request.args.get('upload_bigquery', 'false').lower() == 'true'
        
        # Subir a BigQuery si se solicita
        if upload_bigquery:
            print("[PROCESS] Uploading to BigQuery...")
            sys.stdout.flush()
            dataset_id = request.args.get('dataset_id')
            table_id = request.args.get('table_id')
            if dataset_id and table_id:
                import pandas as pd
                df = pd.read_excel(io.BytesIO(processed_content))
                success = venezuela.upload_to_bigquery(
                    df, credentials, project_id, dataset_id, table_id
                )
                response_data['uploads']['bigquery'] = {
                    'success': success,
                    'dataset': dataset_id,
                    'table': table_id
                }
                print(f"[PROCESS] BigQuery upload result: {success}")
                sys.stdout.flush()
            else:
                print("[PROCESS] BigQuery upload failed: missing dataset_id or table_id")
                sys.stdout.flush()
                response_data['uploads']['bigquery'] = {
                    'success': False,
                    'message': 'dataset_id and table_id are required'
                }
        
        # Siempre devolver JSON con la información (incluyendo la URL de descarga)
        print("[PROCESS] Request completed successfully")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"[PROCESS] Error: {str(e)}")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'error': 'Processing failed',
            'message': str(e)
        }), 500


def normalize_column_name_for_grist(column_name: str) -> str:
    """
    Normaliza el nombre de una columna para que sea compatible con Grist.
    
    Reglas:
    1. Espacios → guiones bajos (_)
    2. Quitar acentos
    3. Si empieza con número o símbolo especial (+, -, etc.), agregar "c" al principio
    4. Convertir guiones a guiones bajos
    5. Ejemplos: "+120" → "c120", "0-30" → "c0_30", "Fecha Recepción" → "Fecha_Recepcion"
    
    Args:
        column_name: Nombre de la columna original
        
    Returns:
        str: Nombre de columna normalizado para Grist
    """
    import unicodedata
    import re
    
    # Convertir a string si no lo es
    col = str(column_name).strip()
    
    if not col:
        return 'column_empty'
    
    # 1. Quitar acentos primero (antes de otras transformaciones)
    # Normalizar a NFD (descomponer caracteres con acentos)
    col = unicodedata.normalize('NFD', col)
    # Eliminar caracteres diacríticos (acentos)
    col = ''.join(c for c in col if unicodedata.category(c) != 'Mn')
    
    # 2. Reemplazar espacios con guiones bajos
    col = col.replace(' ', '_')
    
    # 3. Reemplazar guiones con guiones bajos
    col = col.replace('-', '_')
    
    # 4. Si empieza con número o símbolo especial (+, -, etc.), agregar "c" al principio
    if col and (col[0].isdigit() or col[0] in ['+', '-', '_', '.']):
        col = 'c' + col
    
    # 5. Limpiar caracteres especiales adicionales (mantener solo letras, números y guiones bajos)
    # Reemplazar múltiples guiones bajos consecutivos por uno solo
    col = re.sub(r'_+', '_', col)
    # Eliminar caracteres no permitidos (mantener solo a-z, A-Z, 0-9, _)
    col = re.sub(r'[^a-zA-Z0-9_]', '', col)
    
    # 6. Eliminar guiones bajos al inicio y final
    col = col.strip('_')
    
    # 7. Asegurar que no esté vacío
    if not col:
        col = 'c' + str(abs(hash(column_name)))[:8]
    
    return col


def add_comentarios_from_grist(df_processed, df_old_grist):
    """
    Agrega las columnas "Comentario" y "Comentario CXP" haciendo pareo con df_old_grist.
    Usa la misma lógica que add_comentarios_columns pero en lugar de BigQuery usa df_old_grist.
    
    Args:
        df_processed: DataFrame procesado al que se le agregarán los comentarios
        df_old_grist: DataFrame con los datos antiguos de Grist que contienen los comentarios
    
    Returns:
        pd.DataFrame: DataFrame con las columnas "Comentario" y "Comentario CXP" agregadas
    """
    import pandas as pd
    
    df_result = df_processed.copy()
    
    # Verificar que exista la columna Número Factura para hacer el pareo
    if 'Número Factura' not in df_result.columns:
        print(f"[API] Warning: Column 'Número Factura' not found. Cannot create comentarios columns")
        sys.stdout.flush()
        df_result['Comentario'] = ''
        df_result['Comentario CXP'] = ''
        return df_result
    
    # Verificar que df_old_grist no esté vacío
    if df_old_grist is None or df_old_grist.empty:
        print(f"[API] Warning: df_old_grist is empty. Cannot create comentarios columns")
        sys.stdout.flush()
        df_result['Comentario'] = ''
        df_result['Comentario CXP'] = ''
        return df_result
    
    print(f"[API] Creating 'Comentario' and 'Comentario CXP' columns using old Grist data...")
    sys.stdout.flush()
    
    # Verificar que existan las columnas necesarias en df_old_grist
    # Las columnas pueden tener nombres diferentes, buscar variaciones
    numero_factura_col = None
    comentario_col = None
    comentario_cxp_col = None
    
    # Buscar columna de número de factura (puede ser "Número Factura" o variaciones)
    for col in df_old_grist.columns:
        col_lower = str(col).strip().lower()
        if 'número factura' in col_lower or 'numero factura' in col_lower or 'n° factura' in col_lower:
            numero_factura_col = col
            break
    
    # Buscar columna de comentario
    for col in df_old_grist.columns:
        col_lower = str(col).strip().lower()
        if 'comentario' in col_lower and 'cxp' not in col_lower:
            comentario_col = col
            break
    
    # Buscar columna de comentario CXP
    for col in df_old_grist.columns:
        col_lower = str(col).strip().lower()
        if 'comentario cxp' in col_lower or 'comentario_cxp' in col_lower:
            comentario_cxp_col = col
            break
    
    if not numero_factura_col:
        print(f"[API] Warning: Column 'Número Factura' not found in df_old_grist. Available columns: {list(df_old_grist.columns)}")
        sys.stdout.flush()
        df_result['Comentario'] = ''
        df_result['Comentario CXP'] = ''
        return df_result
    
    # Crear diccionarios de pareo
    comentario_mapping = {}
    comentario_cxp_mapping = {}
    
    for _, row in df_old_grist.iterrows():
        numero_factura = str(row[numero_factura_col]).strip() if pd.notna(row[numero_factura_col]) else ''
        comentario = str(row[comentario_col]).strip() if comentario_col and pd.notna(row[comentario_col]) else ''
        comentario_cxp = str(row[comentario_cxp_col]).strip() if comentario_cxp_col and pd.notna(row[comentario_cxp_col]) else ''
        
        if numero_factura:
            # Normalizar el número de factura para el pareo
            numero_factura_normalized = numero_factura.replace(' ', '').replace('\t', '').replace('\n', '').upper()
            if comentario:
                comentario_mapping[numero_factura_normalized] = comentario
            if comentario_cxp:
                comentario_cxp_mapping[numero_factura_normalized] = comentario_cxp
    
    print(f"[API] Created mappings: {len(comentario_mapping)} comentarios, {len(comentario_cxp_mapping)} comentarios CXP")
    sys.stdout.flush()
    
    # Inicializar las nuevas columnas con valores vacíos
    df_result['Comentario'] = ''
    df_result['Comentario CXP'] = ''
    
    # Convertir Número Factura a string para hacer el pareo
    df_result['Número Factura'] = df_result['Número Factura'].astype(str)
    
    # Hacer el pareo: buscar cada valor de Número Factura en los diccionarios
    matched_count = 0
    for idx, numero_factura in df_result['Número Factura'].items():
        # Normalizar el valor de Número Factura eliminando todos los espacios
        numero_factura_normalized = str(numero_factura).strip().replace(' ', '').replace('\t', '').replace('\n', '').upper()
        # Buscar coincidencia con la versión normalizada
        if numero_factura_normalized in comentario_mapping:
            df_result.at[idx, 'Comentario'] = comentario_mapping[numero_factura_normalized]
            matched_count += 1
        if numero_factura_normalized in comentario_cxp_mapping:
            df_result.at[idx, 'Comentario CXP'] = comentario_cxp_mapping[numero_factura_normalized]
    
    print(f"[API] Matched {matched_count} out of {len(df_result)} rows with comentarios from old Grist data")
    if matched_count < len(df_result):
        unmatched = len(df_result) - matched_count
        print(f"[API] Warning: {unmatched} rows could not be matched with comentarios")
    sys.stdout.flush()
    
    return df_result


def process_grist(df_processed, credentials=None, project_id=None, df_old_grist=None):
    """
    Procesa datos con Grist:
    1. Guarda la tabla actual de Grist en una variable (o usa df_old_grist si se proporciona)
    2. Borra todas las filas de la tabla en Grist
    3. Monta el DataFrame procesado a Grist
    4. Monta la tabla antigua en BigQuery
    
    Args:
        df_processed: DataFrame procesado de venezuela.py (con comentarios ya agregados)
        credentials: Credenciales de GCP (opcional, necesario para BigQuery)
        project_id: ID del proyecto de GCP (opcional, necesario para BigQuery)
        df_old_grist: DataFrame con datos antiguos de Grist (opcional, si no se proporciona se obtiene de Grist)
    
    Returns:
        dict: Resultado de la operación con información de éxito/error
    """
    import pandas as pd
    
    result = {
        'success': True,
        'grist_old_data_rows': 0,  # Número de filas de datos antiguos (no el DataFrame completo)
        'grist_old_data_saved': False,
        'grist_cleared': False,
        'grist_new_data_uploaded': False,
        'bigquery_old_data_uploaded': False,
        'errors': []
    }
    
    try:
        # 1. Guardar la tabla actual de Grist en una variable (o usar la proporcionada)
        if df_old_grist is not None:
            print("[GRIST] Step 1: Using provided df_old_grist...")
            sys.stdout.flush()
            result['grist_old_data_rows'] = len(df_old_grist)
            result['grist_old_data_saved'] = True
            print(f"[GRIST] Using {len(df_old_grist)} rows from provided df_old_grist")
            sys.stdout.flush()
        else:
            print("[GRIST] Step 1: Saving current Grist table data...")
            sys.stdout.flush()
            url_records = f'{SERVER_URL}/{DOC_ID}/tables/{TABLE_ID}/records'
            response = requests.get(url_records, headers=HEADERS)
            
            if response.status_code != 200:
                error_msg = f"Error getting Grist data: {response.status_code} - {response.text}"
                print(f"[GRIST] {error_msg}")
                sys.stdout.flush()
                result['errors'].append(error_msg)
                result['success'] = False
                return result
            
            data_grist_table = response.json()
            records = data_grist_table.get('records', [])
            
            # Convertir los registros de Grist a DataFrame
            df_old_grist = None
            if records:
                # Los registros de Grist vienen con estructura {id: X, fields: {...}}
                # Necesitamos extraer solo los fields
                records_data = []
                for record in records:
                    if 'fields' in record:
                        records_data.append(record['fields'])
                
                if records_data:
                    df_old_grist = pd.DataFrame(records_data)
                    result['grist_old_data_rows'] = len(df_old_grist)
                    result['grist_old_data_saved'] = True
                    print(f"[GRIST] Saved {len(df_old_grist)} rows from current Grist table")
                    sys.stdout.flush()
                else:
                    print("[GRIST] No data fields found in Grist records")
                    sys.stdout.flush()
            else:
                print("[GRIST] No records found in Grist table (table is empty)")
                sys.stdout.flush()
        
        # 2. Borrar todas las filas de la tabla en Grist
        print("[GRIST] Step 2: Deleting all rows from Grist table...")
        sys.stdout.flush()
        
        # Obtener IDs de registros para borrar (si no se proporcionó df_old_grist, ya tenemos records)
        ids_a_borrar = []
        if df_old_grist is None or not result.get('grist_old_data_saved'):
            # Si no se proporcionó df_old_grist, obtener los IDs de la respuesta anterior
            if 'records' in locals():
                ids_a_borrar = [record['id'] for record in records if 'id' in record]
        else:
            # Si se proporcionó df_old_grist, necesitamos obtener los IDs de Grist
            try:
                url_records = f'{SERVER_URL}/{DOC_ID}/tables/{TABLE_ID}/records'
                response = requests.get(url_records, headers=HEADERS)
                if response.status_code == 200:
                    data_grist_table = response.json()
                    records = data_grist_table.get('records', [])
                    ids_a_borrar = [record['id'] for record in records if 'id' in record]
            except Exception as e:
                print(f"[GRIST] Warning: Could not get record IDs for deletion: {str(e)}")
                sys.stdout.flush()
        
        if ids_a_borrar:
            delete_response = requests.post(
                f'{SERVER_URL}/{DOC_ID}/tables/{TABLE_ID}/data/delete',
                headers=HEADERS,
                json=ids_a_borrar
            )
            
            if delete_response.status_code in [200, 204]:
                result['grist_cleared'] = True
                print(f"[GRIST] Deleted {len(ids_a_borrar)} old records from Grist")
                sys.stdout.flush()
            else:
                error_msg = f"Error deleting Grist data: {delete_response.status_code} - {delete_response.text}"
                print(f"[GRIST] {error_msg}")
                sys.stdout.flush()
                result['errors'].append(error_msg)
        else:
            result['grist_cleared'] = True
            print("[GRIST] No records to delete (table was already empty)")
            sys.stdout.flush()
        
        # 3. Montar el DataFrame procesado a Grist
        print("[GRIST] Step 3: Uploading processed DataFrame to Grist...")
        sys.stdout.flush()
        
        # Convertir Timestamps y otros tipos no serializables a strings antes de convertir a dict
        df_for_grist = df_processed.copy()
        for col in df_for_grist.columns:
            # Convertir columnas de fecha/hora a string
            if pd.api.types.is_datetime64_any_dtype(df_for_grist[col]):
                df_for_grist[col] = df_for_grist[col].astype(str)
            # Convertir NaN/NaT a None (que es serializable en JSON)
            elif df_for_grist[col].dtype == 'object':
                df_for_grist[col] = df_for_grist[col].where(pd.notna(df_for_grist[col]), None)
        
        # Convertir a dict usando date_format para manejar fechas
        df_processed_dict = df_for_grist.to_dict(orient='records')
        
        # Convertir cualquier Timestamp, NaN, NaT u otros tipos no serializables restantes
        def convert_to_json_serializable(obj):
            import numpy as np
            
            # Manejar tipos iterables primero (antes de verificar valores individuales)
            if isinstance(obj, dict):
                return {k: convert_to_json_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [convert_to_json_serializable(item) for item in obj]
            elif isinstance(obj, (pd.Series, pd.Index)):
                return [convert_to_json_serializable(item) for item in obj]
            elif isinstance(obj, np.ndarray):
                return [convert_to_json_serializable(item) for item in obj.tolist()]
            
            # Ahora manejar valores escalares
            # Verificar si es un Timestamp
            if isinstance(obj, pd.Timestamp):
                return str(obj)
            
            # Verificar si es un tipo numpy escalar
            if isinstance(obj, (np.integer, np.floating)):
                return obj.item()
            
            # Verificar NaN solo para valores escalares (no arrays)
            # Usar try/except para evitar el error con arrays
            try:
                # Solo verificar NaN para tipos numéricos escalares
                if isinstance(obj, (int, float)) and not isinstance(obj, bool):
                    # Verificar si es NaN de forma segura
                    if isinstance(obj, float) and (obj != obj or str(obj) == 'nan'):  # NaN != NaN es True
                        return None
            except (ValueError, TypeError):
                pass
            
            # Verificar si es un tipo de pandas que necesita conversión
            if isinstance(obj, (pd.Int64Dtype, pd.Float64Dtype)):
                return None
            
            # Verificar si tiene método item() para tipos numpy
            if hasattr(obj, 'item') and not isinstance(obj, (str, bytes)):
                try:
                    return obj.item()
                except (ValueError, AttributeError, TypeError):
                    pass
            
            return obj
        
        df_processed_dict = convert_to_json_serializable(df_processed_dict)
        
        # Subir en lotes para evitar error 413 (request entity too large)
        # El tamaño del lote es configurable mediante variable de entorno
        # Por defecto 100 filas (reducido porque "Links Drive Preview" puede ser grande)
        grist_batch_size_env = os.getenv('GRIST_BATCH_SIZE')
        if grist_batch_size_env:
            try:
                batch_size = int(grist_batch_size_env)
                if batch_size < 1:
                    batch_size = 100
            except:
                batch_size = 100
        else:
            batch_size = 100  # Reducido de 500 a 100 por defecto
        
        total_rows = len(df_processed_dict)
        uploaded_rows = 0
        failed_batches = []
        
        print(f"[GRIST] Uploading {total_rows} rows in batches of {batch_size}...")
        print(f"[GRIST] Note: Batch size can be configured with GRIST_BATCH_SIZE environment variable")
        sys.stdout.flush()
        
        for i in range(0, total_rows, batch_size):
            batch = df_processed_dict[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_rows + batch_size - 1) // batch_size
            
            # Calcular tamaño aproximado del batch en bytes ANTES de limpiar
            try:
                batch_json = json.dumps(batch)
                batch_size_bytes = len(batch_json.encode('utf-8'))
                batch_size_mb = batch_size_bytes / (1024 * 1024)
                batch_size_kb = batch_size_bytes / 1024
            except Exception as e:
                batch_size_mb = 0
                batch_size_kb = 0
                batch_size_bytes = 0
                print(f"[GRIST] Warning: Could not calculate batch size: {str(e)}")
                sys.stdout.flush()
            
            # Verificar si el batch es demasiado grande (más de 5MB es probable que falle)
            MAX_BATCH_SIZE_MB = 5.0
            if batch_size_mb > MAX_BATCH_SIZE_MB:
                print(f"[GRIST] WARNING: Batch {batch_num} is too large ({batch_size_mb:.2f} MB)")
                print(f"[GRIST] Grist typically has a limit around 5-10 MB per request")
                print(f"[GRIST] Consider reducing GRIST_BATCH_SIZE environment variable (current: {batch_size})")
                sys.stdout.flush()
            
            # Mostrar información del batch
            print(f"[GRIST] ========================================")
            print(f"[GRIST] Batch {batch_num}/{total_batches} Details:")
            print(f"[GRIST]   - Rows in batch: {len(batch)}")
            print(f"[GRIST]   - Row range: {i+1} to {min(i+batch_size, total_rows)}")
            print(f"[GRIST]   - Approximate size: {batch_size_mb:.2f} MB ({batch_size_kb:.2f} KB, {batch_size_bytes:,} bytes)")
            print(f"[GRIST]   - Columns: {len(batch[0].keys()) if batch else 0}")
            if batch:
                # Verificar que todas las claves sean strings válidos
                first_record = batch[0]
                column_names = list(first_record.keys())
                print(f"[GRIST]   - All column names: {column_names}")
                
                # Verificar si hay columnas con nombres numéricos o problemáticos
                problematic_cols = [col for col in column_names if isinstance(col, (int, float)) or str(col).isdigit()]
                if problematic_cols:
                    print(f"[GRIST]   WARNING: Found problematic column names (numeric): {problematic_cols}")
                
                print(f"[GRIST]   - Sample columns: {column_names[:5]}...")
                # Mostrar una muestra del primer registro
                print(f"[GRIST]   - First record sample:")
                for key, value in list(first_record.items())[:5]:
                    value_str = str(value)[:50] if value is not None else "None"
                    key_type = type(key).__name__
                    print(f"[GRIST]     {key} (type: {key_type}): {value_str}")
                
                # Verificar estructura del batch
                print(f"[GRIST]   - Batch structure check:")
                print(f"[GRIST]     - Is list: {isinstance(batch, list)}")
                print(f"[GRIST]     - First item is dict: {isinstance(batch[0], dict) if batch else False}")
                if batch and isinstance(batch[0], dict):
                    print(f"[GRIST]     - First item keys type: {[type(k).__name__ for k in batch[0].keys()][:5]}")
            print(f"[GRIST] ========================================")
            print(f"[GRIST] Uploading batch {batch_num}/{total_batches}...")
            sys.stdout.flush()
            
            # Limpiar el batch: normalizar nombres de columnas y asegurar que todas las claves sean válidas
            cleaned_batch = []
            column_mapping = {}  # Para mapear nombres originales a normalizados
            
            # Primero, crear el mapeo de nombres de columnas
            if batch:
                original_keys = list(batch[0].keys())
                for orig_key in original_keys:
                    normalized_key = normalize_column_name_for_grist(orig_key)
                    column_mapping[orig_key] = normalized_key
                    if orig_key != normalized_key:
                        print(f"[GRIST] Column name normalized: '{orig_key}' → '{normalized_key}'")
                        sys.stdout.flush()
            
            # Aplicar normalización a cada registro
            for record in batch:
                cleaned_record = {}
                for key, value in record.items():
                    # Normalizar el nombre de la columna
                    normalized_key = column_mapping.get(key, normalize_column_name_for_grist(key))
                    
                    # Asegurar que el valor sea serializable
                    if value is None or (isinstance(value, float) and pd.isna(value)):
                        cleaned_record[normalized_key] = None
                    else:
                        cleaned_record[normalized_key] = value
                cleaned_batch.append(cleaned_record)
            
            batch = cleaned_batch
            
            # Recalcular el tamaño después de limpiar (puede ser diferente)
            try:
                cleaned_batch_json = json.dumps(batch)
                cleaned_batch_size_bytes = len(cleaned_batch_json.encode('utf-8'))
                cleaned_batch_size_mb = cleaned_batch_size_bytes / (1024 * 1024)
                cleaned_batch_size_kb = cleaned_batch_size_bytes / 1024
                
                MAX_BATCH_SIZE_MB = 5.0
                if cleaned_batch_size_mb > MAX_BATCH_SIZE_MB:
                    print(f"[GRIST] WARNING: Cleaned batch {batch_num} is too large ({cleaned_batch_size_mb:.2f} MB)")
                    print(f"[GRIST] Grist typically has a limit around 5-10 MB per request")
                    print(f"[GRIST] Consider reducing GRIST_BATCH_SIZE environment variable (current: {batch_size})")
                    sys.stdout.flush()
                else:
                    print(f"[GRIST] Cleaned batch size: {cleaned_batch_size_mb:.2f} MB ({cleaned_batch_size_kb:.2f} KB)")
                    sys.stdout.flush()
            except Exception as e:
                print(f"[GRIST] Warning: Could not calculate cleaned batch size: {str(e)}")
                sys.stdout.flush()
            
            # Mostrar el mapeo de columnas normalizadas
            if column_mapping:
                print(f"[GRIST] Column name mappings (showing first 10):")
                for orig, norm in list(column_mapping.items())[:10]:
                    if orig != norm:
                        print(f"[GRIST]   '{orig}' → '{norm}'")
                sys.stdout.flush()
            
            # Convertir el formato a lo que Grist espera:
            # Grist espera: {"records": [{"fields": {...}}, {"fields": {...}}]}
            grist_format_batch = {
                "records": [
                    {"fields": record} for record in batch
                ]
            }
            
            # Debug: Verificar el formato del JSON antes de enviar
            try:
                import json
                # Mostrar una muestra del JSON serializado
                test_json = json.dumps(grist_format_batch, ensure_ascii=False, default=str, indent=2)
                print(f"[GRIST] Debug - Grist format JSON (first 600 chars):")
                print(test_json[:600])
                print(f"[GRIST] Debug - JSON structure: {type(grist_format_batch).__name__}")
                print(f"[GRIST] Debug - Records count: {len(grist_format_batch.get('records', []))}")
                if grist_format_batch.get('records'):
                    print(f"[GRIST] Debug - First record fields keys (first 5): {list(grist_format_batch['records'][0]['fields'].keys())[:5]}")
                sys.stdout.flush()
            except Exception as e:
                print(f"[GRIST] Warning: Could not verify batch format: {str(e)}")
                import traceback
                traceback.print_exc()
                sys.stdout.flush()
            
            try:
                # Serializar manualmente el JSON para tener más control
                import json
                json_data = json.dumps(grist_format_batch, ensure_ascii=False, default=str, indent=2)
                
                # Guardar el JSON en un archivo local para debugging
                from datetime import datetime
                debug_dir = "grist_debug"
                if not os.path.exists(debug_dir):
                    os.makedirs(debug_dir)
                    print(f"[GRIST] Created debug directory: {debug_dir}")
                    sys.stdout.flush()
                
                debug_filename = f"grist_batch_{batch_num}_{total_batches}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                debug_filepath = os.path.join(debug_dir, debug_filename)
                
                try:
                    with open(debug_filepath, 'w', encoding='utf-8') as f:
                        f.write(json_data)
                    print(f"[GRIST] Debug JSON saved to: {debug_filepath}")
                    print(f"[GRIST] JSON file size: {len(json_data)} bytes")
                    sys.stdout.flush()
                except Exception as e:
                    print(f"[GRIST] Warning: Could not save debug JSON file: {str(e)}")
                    sys.stdout.flush()
                
                # Verificar que el JSON sea válido
                try:
                    json.loads(json_data)  # Validar que se puede parsear de vuelta
                except json.JSONDecodeError as e:
                    print(f"[GRIST] ERROR: Invalid JSON generated: {str(e)}")
                    sys.stdout.flush()
                    raise
                
                # Enviar con data en lugar de json para tener más control
                upload_response = requests.post(
                    f'{SERVER_URL}/{DOC_ID}/tables/{TABLE_ID}/records',
                    headers=HEADERS,
                    data=json_data.encode('utf-8'),
                    timeout=300  # Timeout de 5 minutos por lote
                )
                
                if upload_response.status_code in [200, 201]:
                    uploaded_rows += len(batch)
                    print(f"[GRIST] Batch {batch_num}/{total_batches} uploaded successfully ({uploaded_rows}/{total_rows} rows)")
                    sys.stdout.flush()
                else:
                    error_msg = f"Error uploading batch {batch_num}/{total_batches}: {upload_response.status_code} - {upload_response.text}"
                    print(f"[GRIST] {error_msg}")
                    sys.stdout.flush()
                    
                    # Debug adicional en caso de error
                    if upload_response.status_code == 400:
                        print(f"[GRIST] Debug - Request URL: {SERVER_URL}/{DOC_ID}/tables/{TABLE_ID}/data")
                        print(f"[GRIST] Debug - Batch length: {len(batch)}")
                        print(f"[GRIST] Debug - First record keys: {list(batch[0].keys())[:10] if batch else 'No batch'}")
                        sys.stdout.flush()
                    
                    failed_batches.append({
                        'batch': batch_num,
                        'rows': len(batch),
                        'error': error_msg
                    })
                    result['errors'].append(error_msg)
            except Exception as e:
                error_msg = f"Exception uploading batch {batch_num}/{total_batches}: {str(e)}"
                print(f"[GRIST] {error_msg}")
                sys.stdout.flush()
                failed_batches.append({
                    'batch': batch_num,
                    'rows': len(batch),
                    'error': error_msg
                })
                result['errors'].append(error_msg)
        
        # Verificar si todos los lotes se subieron correctamente
        if uploaded_rows == total_rows:
            result['grist_new_data_uploaded'] = True
            print(f"[GRIST] Successfully uploaded all {uploaded_rows} rows to Grist in {total_batches} batch(es)")
            sys.stdout.flush()
        elif uploaded_rows > 0:
            result['grist_new_data_uploaded'] = True  # Parcialmente exitoso
            result['success'] = False  # Pero marcamos como no completamente exitoso
            print(f"[GRIST] Partially uploaded: {uploaded_rows}/{total_rows} rows. Failed batches: {len(failed_batches)}")
            sys.stdout.flush()
            result['failed_batches'] = failed_batches
        else:
            result['grist_new_data_uploaded'] = False
            result['success'] = False
            print(f"[GRIST] Failed to upload any rows. All {total_batches} batch(es) failed")
            sys.stdout.flush()
        
        # 4. Montar la tabla antigua en BigQuery (solo si hay datos antiguos y credenciales)
        if df_old_grist is not None and not df_old_grist.empty and credentials and project_id:
            print("[GRIST] Step 4: Uploading old Grist data to BigQuery...")
            sys.stdout.flush()
            
            # Obtener configuración de BigQuery desde variables de entorno
            bq_dataset_id = os.getenv('BIGQUERY_DATASET_ID')
            bq_table_id = os.getenv('BIGQUERY_TABLE_ID')  # Tabla para historial
            
            if bq_dataset_id and bq_table_id:
                # Usar WRITE_APPEND para agregar al historial
                # Pasar df_processed como referencia para convertir nombres de columnas normalizados a originales
                success = venezuela.upload_to_bigquery(
                    df_old_grist, 
                    credentials, 
                    project_id, 
                    bq_dataset_id, 
                    bq_table_id,
                    write_disposition='WRITE_APPEND',
                    df_reference=df_processed  # DataFrame de referencia con nombres originales
                )
                
                if success:
                    result['bigquery_old_data_uploaded'] = True
                    print(f"[GRIST] Uploaded {len(df_old_grist)} old rows to BigQuery: {bq_dataset_id}.{bq_table_id}")
                    sys.stdout.flush()
                else:
                    error_msg = "Failed to upload old data to BigQuery"
                    print(f"[GRIST] {error_msg}")
                    sys.stdout.flush()
                    result['errors'].append(error_msg)
            else:
                print("[GRIST] Warning: BIGQUERY_DATASET_ID or BIGQUERY_HISTORY_TABLE_ID not configured. Skipping BigQuery upload")
                sys.stdout.flush()
        elif df_old_grist is None or df_old_grist.empty:
            print("[GRIST] No old data to upload to BigQuery (table was empty)")
            sys.stdout.flush()
        elif not credentials or not project_id:
            print("[GRIST] Warning: Credentials or project_id not provided. Skipping BigQuery upload")
            sys.stdout.flush()
        
        print("[GRIST] Process completed successfully")
        sys.stdout.flush()
        return result
        
    except Exception as e:
        error_msg = f"Error in process_grist: {str(e)}"
        print(f"[GRIST] {error_msg}")
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        result['success'] = False
        result['errors'].append(error_msg)
        return result



# ============================================================================
# ENDPOINTS DE AUTENTICACIÓN GMAIL (OAuth2)
# ============================================================================

@app.route('/auth/gmail/status', methods=['GET'])
def gmail_auth_status():
    """
    Verifica el estado de la autorización de Gmail OAuth2.
    
    Returns:
        JSON con el estado de la autorización:
        {
            "authorized": true/false,
            "email": "usuario@gmail.com" (si autorizado),
            "token_exists": true/false,
            "token_valid": true/false
        }
    """
    print("=" * 50)
    print("[GMAIL-AUTH] Checking authorization status")
    sys.stdout.flush()
    
    status = emailSend.check_gmail_auth_status()
    
    print(f"[GMAIL-AUTH] Status: authorized={status.get('authorized')}, email={status.get('email')}")
    print("=" * 50)
    sys.stdout.flush()
    
    return jsonify(status), 200


@app.route('/auth/gmail', methods=['GET'])
def gmail_auth_start():
    """
    Inicia el flujo de autorización OAuth2 para Gmail.
    Retorna la URL donde el usuario debe autorizar la aplicación.
    
    Query Parameters:
        - redirect_uri: URI de redirección después de autorizar (opcional)
                       Si no se proporciona, usa la configurada en client_secret.json
    
    Returns:
        JSON con la URL de autorización:
        {
            "success": true,
            "authorization_url": "https://accounts.google.com/...",
            "state": "...",
            "instructions": "..."
        }
    """
    print("=" * 50)
    print("[GMAIL-AUTH] Starting OAuth2 flow")
    sys.stdout.flush()
    
    # Obtener redirect_uri del query parameter o usar el default
    redirect_uri = request.args.get('redirect_uri')
    
    # Si no se proporciona, intentar construir uno basado en el host actual
    if not redirect_uri:
        # Usar variable de entorno o construir desde request
        redirect_uri = os.getenv('GMAIL_OAUTH_REDIRECT_URI')
        if not redirect_uri:
            # Construir basándose en el request actual
            host = request.host_url.rstrip('/')
            redirect_uri = f"{host}/auth/gmail/callback"
    
    print(f"[GMAIL-AUTH] Redirect URI: {redirect_uri}")
    sys.stdout.flush()
    
    auth_url, state, error = emailSend.get_authorization_url(
        redirect_uri=redirect_uri
    )
    
    if error:
        print(f"[GMAIL-AUTH] Error: {error}")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'error': error
        }), 400
    
    print(f"[GMAIL-AUTH] Authorization URL generated")
    print("=" * 50)
    sys.stdout.flush()
    
    return jsonify({
        'success': True,
        'authorization_url': auth_url,
        'state': state,
        'redirect_uri': redirect_uri,
        'instructions': 'Visita la authorization_url en tu navegador, autoriza la aplicación, y serás redirigido al callback con un código.'
    }), 200


@app.route('/auth/gmail/callback', methods=['GET', 'POST'])
def gmail_auth_callback():
    """
    Callback para recibir el código de autorización de Google.
    Puede recibir el código como query parameter (GET) o en el body (POST).
    
    GET Query Parameters:
        - code: Código de autorización de Google
        - state: Estado para verificar (opcional)
        - error: Error si el usuario rechazó (opcional)
    
    POST Body (JSON):
        {
            "code": "código de autorización",
            "redirect_uri": "URI usada en la autorización"
        }
    
    Returns:
        JSON con el resultado:
        {
            "success": true,
            "email": "usuario@gmail.com",
            "message": "Gmail authorization successful"
        }
    """
    print("=" * 50)
    print("[GMAIL-AUTH] Callback received")
    print(f"[GMAIL-AUTH] Method: {request.method}")
    sys.stdout.flush()
    
    code = None
    redirect_uri = None
    
    if request.method == 'GET':
        # Verificar si hay error
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'User denied access')
            print(f"[GMAIL-AUTH] Authorization denied: {error} - {error_description}")
            print("=" * 50)
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': error,
                'message': error_description
            }), 400
        
        code = request.args.get('code')
        # Reconstruir redirect_uri
        host = request.host_url.rstrip('/')
        redirect_uri = os.getenv('GMAIL_OAUTH_REDIRECT_URI', f"{host}/auth/gmail/callback")
        
    elif request.method == 'POST':
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Request must be JSON'
            }), 400
        
        data = request.get_json()
        code = data.get('code')
        redirect_uri = data.get('redirect_uri')
        
        if not redirect_uri:
            host = request.host_url.rstrip('/')
            redirect_uri = os.getenv('GMAIL_OAUTH_REDIRECT_URI', f"{host}/auth/gmail/callback")
    
    if not code:
        print("[GMAIL-AUTH] Error: No authorization code provided")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'error': 'No authorization code provided',
            'message': 'The "code" parameter is required'
        }), 400
    
    print(f"[GMAIL-AUTH] Exchanging code for token...")
    print(f"[GMAIL-AUTH] Redirect URI: {redirect_uri}")
    sys.stdout.flush()
    
    success, result = emailSend.exchange_code_for_token(
        code=code,
        redirect_uri=redirect_uri
    )
    
    if success:
        print(f"[GMAIL-AUTH] Authorization successful for: {result.get('email')}")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'success': True,
            'email': result.get('email'),
            'message': 'Gmail authorization successful! You can now send emails.'
        }), 200
    else:
        print(f"[GMAIL-AUTH] Authorization failed: {result.get('error')}")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'error': result.get('error')
        }), 400


# ============================================================================
# ENDPOINTS DE ENVÍO DE EMAIL
# ============================================================================

@app.route('/send-email/factura', methods=['POST'])
def send_email_factura_endpoint():
    """
    Endpoint específico para enviar correos de facturas.
    Busca el correo del destinatario usando el valor de "Tienda" en el Google Sheet.
    
    IMPORTANTE: Requiere autorización previa via /auth/gmail
    
    Request Body (JSON):
    {
        "Numero_Factura": "FAC-001",
        "Tienda": "Tienda Centro",
        "Area": "Zona Norte",
        "PDF_View": "https://link-al-pdf.com/factura.pdf",
        "subject": "Factura {Numero_Factura} - {Tienda}",  // Opcional, tiene default
        "body_text": "...",  // Opcional, tiene default
        "body_html": "..."   // Opcional
    }
    
    Variables de entorno requeridas en .env:
        - EMAIL_SPREADSHEET_ID: ID del Google Sheet con los contactos
        - EMAIL_WORKSHEET_NAME: Nombre de la hoja (default: Sheet1)
        - EMAIL_SEARCH_COLUMN: Columna para buscar (default: Tienda)
        - EMAIL_EMAIL_COLUMN: Columna con el correo (default: Email)
    
    Returns:
        JSON con el resultado del envío
    """
    print("=" * 50)
    print("[SEND-EMAIL-FACTURA] Endpoint called")
    print(f"[SEND-EMAIL-FACTURA] Method: {request.method}")
    print(f"[SEND-EMAIL-FACTURA] Content-Type: {request.content_type}")
    sys.stdout.flush()
    
    try:
        # Verificar que se envió JSON
        if not request.is_json:
            print("[SEND-EMAIL-FACTURA] Error: Request must be JSON")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'Request must be JSON',
                'message': 'Please send a JSON body with Content-Type: application/json'
            }), 400
        
        data = request.get_json()
        
        # Validar campos requeridos para factura
        required_fields = ['Numero_Factura', 'Tienda', 'Area', 'PDF_View']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            print(f"[SEND-EMAIL-FACTURA] Error: Missing required fields: {missing_fields}")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'missing_fields': missing_fields,
                'message': f'Please provide: {", ".join(missing_fields)}'
            }), 400
        
        # Extraer datos de la factura
        numero_factura = data['Numero_Factura']
        tienda = data['Tienda']
        area = data['Area']
        pdf_view = data['PDF_View']
        
        # Obtener configuración del Sheet
        spreadsheet_id = data.get('spreadsheet_id', EMAIL_SPREADSHEET_ID)
        worksheet_name = data.get('worksheet_name', EMAIL_WORKSHEET_NAME)
        search_column = 'Tienda'  # Columna fija para buscar
        email_column = 'Correo Electrónico'    # Columna fija con el correo
        
        if not spreadsheet_id:
            print("[SEND-EMAIL-FACTURA] Error: No spreadsheet_id configured")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'No spreadsheet_id configured',
                'message': 'Please set EMAIL_SPREADSHEET_ID in .env or provide spreadsheet_id in request'
            }), 400
        
        # Subject y body con valores por defecto
        default_subject = f"Factura {numero_factura} - {tienda}"
        default_body_text = f"""
Estimado(a),

Se adjunta la información de la factura:

Número de Factura: {numero_factura}
Tienda: {tienda}
Área: {area}

Ver PDF: {pdf_view}

Saludos cordiales.
"""
        
        default_body_html = f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6;">
    <p>Estimado(a),</p>
    
    <p>Se adjunta la información de la factura:</p>
    
    <table style="border-collapse: collapse; margin: 20px 0;">
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5;"><strong>Número de Factura</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{numero_factura}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5;"><strong>Tienda</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{tienda}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd; background-color: #f5f5f5;"><strong>Área</strong></td>
            <td style="padding: 8px; border: 1px solid #ddd;">{area}</td>
        </tr>
    </table>
    
    <p><a href="{pdf_view}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Ver PDF de la Factura</a></p>
    
    <p>Saludos cordiales.</p>
</body>
</html>
"""
        
        subject = data.get('subject', default_subject)
        body_text = data.get('body_text', default_body_text)
        body_html = data.get('body_html', default_body_html)
        
        # Obtener credenciales OAuth2 para Gmail
        gmail_creds, gmail_error = emailSend.get_gmail_credentials_oauth2()
        
        if gmail_error or not gmail_creds:
            print(f"[SEND-EMAIL-FACTURA] Error: Gmail not authorized - {gmail_error}")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'Gmail not authorized',
                'message': gmail_error or 'Please authorize Gmail first via GET /auth/gmail',
                'auth_required': True,
                'auth_endpoint': '/auth/gmail'
            }), 401
        
        # Obtener credenciales de Service Account para Sheets
        sheets_credentials, project_id = get_credentials()
        
        # Obtener sender
        sender = data.get('sender', os.getenv('EMAIL_SENDER', ''))
        if not sender:
            auth_status = emailSend.check_gmail_auth_status()
            sender = auth_status.get('email', '')
        
        print(f"[SEND-EMAIL-FACTURA] Numero Factura: {numero_factura}")
        print(f"[SEND-EMAIL-FACTURA] Tienda: {tienda}")
        print(f"[SEND-EMAIL-FACTURA] Area: {area}")
        print(f"[SEND-EMAIL-FACTURA] PDF View: {pdf_view}")
        print(f"[SEND-EMAIL-FACTURA] Spreadsheet: {spreadsheet_id}")
        print(f"[SEND-EMAIL-FACTURA] Search: {search_column} = '{tienda}'")
        print(f"[SEND-EMAIL-FACTURA] Sender: {sender}")
        sys.stdout.flush()
        
        # Variables de plantilla para reemplazar en subject/body
        template_variables = {
            'Numero_Factura': numero_factura,
            'Tienda': tienda,
            'Area': area,
            'PDF_View': pdf_view
        }
        
        # Enviar correo con búsqueda en Sheet
        success, result = emailSend.send_email_with_sheet_lookup(
            credentials=gmail_creds,
            spreadsheet_id=spreadsheet_id,
            worksheet_name=worksheet_name,
            search_column=search_column,
            search_value=tienda,  # Buscar por Tienda
            email_column=email_column,
            sender=sender,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            cc=data.get('cc'),
            bcc=data.get('bcc'),
            template_variables=template_variables,
            sheets_credentials=sheets_credentials
        )
        
        if success:
            print(f"[SEND-EMAIL-FACTURA] Email sent successfully to: {result.get('recipient_email')}")
            print("=" * 50)
            sys.stdout.flush()
            return jsonify({
                'success': True,
                'message': f"Email sent successfully to {result.get('recipient_email')}",
                'data': {
                    **result,
                    'factura': {
                        'numero': numero_factura,
                        'tienda': tienda,
                        'area': area,
                        'pdf_view': pdf_view
                    }
                }
            }), 200
        else:
            print(f"[SEND-EMAIL-FACTURA] Failed to send email: {result.get('error')}")
            print("=" * 50)
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error'),
                'data': result
            }), 400
        
    except Exception as e:
        print(f"[SEND-EMAIL-FACTURA] Error: {str(e)}")
        print("=" * 50)
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/send-email', methods=['POST'])
def send_email_endpoint():
    """
    Endpoint para enviar correos electrónicos usando Gmail OAuth2.
    Busca el correo del destinatario en un Google Sheet y envía el email.
    
    IMPORTANTE: Requiere autorización previa via /auth/gmail
    
    Request Body (JSON):
    {
        "spreadsheet_id": "ID del Google Sheets con la información de contactos",
        "worksheet_name": "Nombre de la hoja (default: 'Sheet1')",
        "search_column": "Nombre de la columna donde buscar (ej: 'Proveedor', 'Tienda')",
        "search_value": "Valor a buscar en esa columna",
        "email_column": "Nombre de la columna que contiene el correo (ej: 'Email', 'Correo')",
        "sender": "Correo del remitente (opcional, usa el correo autorizado)",
        "subject": "Asunto del correo (puede contener {variables} de la fila)",
        "body_text": "Cuerpo del correo en texto plano (puede contener {variables})",
        "body_html": "Cuerpo del correo en HTML (opcional)",
        "cc": ["lista", "de", "correos", "en", "copia"],
        "bcc": ["lista", "de", "correos", "en", "copia", "oculta"],
        "template_variables": {"variable": "valor"}
    }
    
    Returns:
        JSON con el resultado del envío
    """
    print("=" * 50)
    print("[SEND-EMAIL] Endpoint called")
    print(f"[SEND-EMAIL] Method: {request.method}")
    print(f"[SEND-EMAIL] Content-Type: {request.content_type}")
    sys.stdout.flush()
    
    try:
        # Verificar que se envió JSON
        if not request.is_json:
            print("[SEND-EMAIL] Error: Request must be JSON")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'Request must be JSON',
                'message': 'Please send a JSON body with Content-Type: application/json'
            }), 400
        
        data = request.get_json()
        
        # Obtener spreadsheet_id y worksheet del request o de variables de entorno
        spreadsheet_id = data.get('spreadsheet_id', EMAIL_SPREADSHEET_ID)
        worksheet_name = data.get('worksheet_name', EMAIL_WORKSHEET_NAME)
        worksheet_gid = data.get('worksheet_gid', EMAIL_WORKSHEET_GID)
        
        # Validar que tengamos spreadsheet_id (del request o del .env)
        if not spreadsheet_id:
            print("[SEND-EMAIL] Error: No spreadsheet_id provided")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'No spreadsheet_id provided',
                'message': 'Please provide spreadsheet_id in the request or set EMAIL_SPREADSHEET_ID in .env'
            }), 400
        
        # Validar campos requeridos (spreadsheet_id ya no es requerido si está en .env)
        required_fields = ['search_column', 'search_value', 'email_column', 'subject', 'body_text']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            print(f"[SEND-EMAIL] Error: Missing required fields: {missing_fields}")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'missing_fields': missing_fields,
                'message': f'Please provide: {", ".join(missing_fields)}'
            }), 400
        
        # Obtener credenciales OAuth2 para Gmail
        gmail_creds, gmail_error = emailSend.get_gmail_credentials_oauth2()
        
        if gmail_error or not gmail_creds:
            print(f"[SEND-EMAIL] Error: Gmail not authorized - {gmail_error}")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'Gmail not authorized',
                'message': gmail_error or 'Please authorize Gmail first via GET /auth/gmail',
                'auth_required': True,
                'auth_endpoint': '/auth/gmail'
            }), 401
        
        # Obtener credenciales de Service Account para Sheets
        sheets_credentials, project_id = get_credentials()
        search_column = data['search_column']
        search_value = data['search_value']
        email_column = data['email_column']
        sender = data.get('sender', os.getenv('EMAIL_SENDER', ''))
        subject = data['subject']
        body_text = data['body_text']
        body_html = data.get('body_html')
        cc = data.get('cc', [])
        bcc = data.get('bcc', [])
        template_variables = data.get('template_variables', {})
        
        # Si no hay sender, usar el email del usuario autorizado
        if not sender:
            auth_status = emailSend.check_gmail_auth_status()
            sender = auth_status.get('email', '')
        
        if not sender:
            print("[SEND-EMAIL] Error: No sender email")
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': 'No sender email',
                'message': 'Could not determine sender email'
            }), 400
        
        print(f"[SEND-EMAIL] Spreadsheet: {spreadsheet_id}")
        print(f"[SEND-EMAIL] Worksheet: {worksheet_name}")
        print(f"[SEND-EMAIL] Search: {search_column} = '{search_value}'")
        print(f"[SEND-EMAIL] Email column: {email_column}")
        print(f"[SEND-EMAIL] Sender: {sender}")
        print(f"[SEND-EMAIL] Subject: {subject}")
        sys.stdout.flush()
        
        # Enviar correo con búsqueda en Sheet
        success, result = emailSend.send_email_with_sheet_lookup(
            credentials=gmail_creds,  # Credenciales OAuth2 para Gmail
            spreadsheet_id=spreadsheet_id,
            worksheet_name=worksheet_name,
            search_column=search_column,
            search_value=search_value,
            email_column=email_column,
            sender=sender,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            cc=cc if cc else None,
            bcc=bcc if bcc else None,
            template_variables=template_variables,
            sheets_credentials=sheets_credentials  # Service Account para Sheets
        )
        
        if success:
            print(f"[SEND-EMAIL] Email sent successfully to: {result.get('recipient_email')}")
            print("=" * 50)
            sys.stdout.flush()
            return jsonify({
                'success': True,
                'message': f"Email sent successfully to {result.get('recipient_email')}",
                'data': result
            }), 200
        else:
            print(f"[SEND-EMAIL] Failed to send email: {result.get('error')}")
            print("=" * 50)
            sys.stdout.flush()
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error'),
                'data': result
            }), 400
        
    except Exception as e:
        print(f"[SEND-EMAIL] Error: {str(e)}")
        print("=" * 50)
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/send-email/bulk', methods=['POST'])
def send_bulk_email_endpoint():
    """
    Endpoint para enviar correos masivos usando Gmail OAuth2.
    
    IMPORTANTE: Requiere autorización previa via /auth/gmail
    
    Request Body (JSON):
    {
        "spreadsheet_id": "ID del Google Sheets",
        "worksheet_name": "Nombre de la hoja (default: 'Sheet1')",
        "email_column": "Columna con los correos",
        "sender": "Correo del remitente (opcional)",
        "subject": "Asunto (puede contener {variables})",
        "body_text": "Cuerpo en texto (puede contener {variables})",
        "body_html": "Cuerpo en HTML (opcional)",
        "filter_criteria": {"columna": "valor"}
    }
    
    Returns:
        JSON con resumen del envío masivo
    """
    print("=" * 50)
    print("[SEND-EMAIL-BULK] Endpoint called")
    print(f"[SEND-EMAIL-BULK] Method: {request.method}")
    sys.stdout.flush()
    
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Request must be JSON'
            }), 400
        
        data = request.get_json()
        
        # Obtener spreadsheet_id y worksheet del request o de variables de entorno
        spreadsheet_id = data.get('spreadsheet_id', EMAIL_SPREADSHEET_ID)
        worksheet_name = data.get('worksheet_name', EMAIL_WORKSHEET_NAME)
        
        # Validar que tengamos spreadsheet_id
        if not spreadsheet_id:
            return jsonify({
                'success': False,
                'error': 'No spreadsheet_id provided',
                'message': 'Please provide spreadsheet_id in the request or set EMAIL_SPREADSHEET_ID in .env'
            }), 400
        
        # Validar campos requeridos (spreadsheet_id ya no es requerido si está en .env)
        required_fields = ['email_column', 'subject', 'body_text']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400
        
        # Obtener credenciales OAuth2 para Gmail
        gmail_creds, gmail_error = emailSend.get_gmail_credentials_oauth2()
        
        if gmail_error or not gmail_creds:
            return jsonify({
                'success': False,
                'error': 'Gmail not authorized',
                'message': gmail_error or 'Please authorize Gmail first via GET /auth/gmail',
                'auth_required': True,
                'auth_endpoint': '/auth/gmail'
            }), 401
        
        # Obtener credenciales de Service Account para Sheets
        sheets_credentials, project_id = get_credentials()
        
        sender = data.get('sender', os.getenv('EMAIL_SENDER', ''))
        if not sender:
            auth_status = emailSend.check_gmail_auth_status()
            sender = auth_status.get('email', '')
        
        if not sender:
            return jsonify({
                'success': False,
                'error': 'No sender email'
            }), 400
        
        results = emailSend.send_bulk_emails(
            credentials=gmail_creds,
            spreadsheet_id=spreadsheet_id,
            worksheet_name=worksheet_name,
            email_column=data['email_column'],
            sender=sender,
            subject=data['subject'],
            body_text=data['body_text'],
            body_html=data.get('body_html'),
            filter_criteria=data.get('filter_criteria'),
            sheets_credentials=sheets_credentials
        )
        
        print(f"[SEND-EMAIL-BULK] Completed: {results.get('sent', 0)} sent, {results.get('failed', 0)} failed")
        print("=" * 50)
        sys.stdout.flush()
        
        success = results.get('error') is None and results.get('sent', 0) > 0
        status_code = 200 if success else 400
        
        return jsonify({
            'success': success,
            'message': f"Sent {results.get('sent', 0)} of {results.get('total', 0)} emails",
            'data': results
        }), status_code
        
    except Exception as e:
        print(f"[SEND-EMAIL-BULK] Error: {str(e)}")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/search-email', methods=['POST'])
def search_email_endpoint():
    """
    Endpoint para buscar un correo en Google Sheets sin enviarlo.
    Útil para verificar que la búsqueda funciona antes de enviar.
    
    Request Body (JSON):
    {
        "spreadsheet_id": "ID del Google Sheets",
        "worksheet_name": "Nombre de la hoja (default: 'Sheet1')",
        "search_column": "Columna donde buscar",
        "search_value": "Valor a buscar",
        "email_column": "Columna con el correo",
        "additional_columns": ["columna1", "columna2"]
    }
    
    Returns:
        JSON con el correo encontrado y datos adicionales
    """
    print("=" * 50)
    print("[SEARCH-EMAIL] Endpoint called")
    sys.stdout.flush()
    
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Request must be JSON'
            }), 400
        
        data = request.get_json()
        
        # Obtener spreadsheet_id y worksheet del request o de variables de entorno
        spreadsheet_id = data.get('spreadsheet_id', EMAIL_SPREADSHEET_ID)
        worksheet_name = data.get('worksheet_name', EMAIL_WORKSHEET_NAME)
        
        # Validar que tengamos spreadsheet_id
        if not spreadsheet_id:
            return jsonify({
                'success': False,
                'error': 'No spreadsheet_id provided',
                'message': 'Please provide spreadsheet_id in the request or set EMAIL_SPREADSHEET_ID in .env'
            }), 400
        
        required_fields = ['search_column', 'search_value', 'email_column']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': 'Missing required fields',
                'missing_fields': missing_fields
            }), 400
        
        # Usar Service Account para leer Sheets
        credentials, project_id = get_credentials()
        
        email, row_data = emailSend.search_email_in_sheet(
            credentials=credentials,
            spreadsheet_id=spreadsheet_id,
            worksheet_name=worksheet_name,
            search_column=data['search_column'],
            search_value=data['search_value'],
            email_column=data['email_column'],
            additional_columns=data.get('additional_columns')
        )
        
        print(f"[SEARCH-EMAIL] Result: {email}")
        print("=" * 50)
        sys.stdout.flush()
        
        if email:
            return jsonify({
                'success': True,
                'message': 'Email found',
                'data': {
                    'email': email,
                    'search_column': data['search_column'],
                    'search_value': data['search_value'],
                    'additional_data': row_data
                }
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'No email found for the given criteria',
                'data': {
                    'search_column': data['search_column'],
                    'search_value': data['search_value']
                }
            }), 404
        
    except Exception as e:
        print(f"[SEARCH-EMAIL] Error: {str(e)}")
        print("=" * 50)
        sys.stdout.flush()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8750))
    print(f"Starting Flask server on port {port}")
    print("=" * 50)
    sys.stdout.flush()
    app.run(host='0.0.0.0', port=port, debug=True)
