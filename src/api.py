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
    Recibe un archivo Excel como form-data con el campo "file", lo procesa y devuelve el resultado.
    
    Query parameters opcionales:
        - upload_bigquery: Si está presente, sube el resultado a BigQuery
        - dataset_id: ID del dataset de BigQuery
        - table_id: ID de la tabla de BigQuery
        - upload_storage: Si está presente, sube el resultado a Cloud Storage
        - bucket_name: Nombre del bucket de Cloud Storage
        - blob_name: Nombre del blob en Cloud Storage
        - upload_sheets: Si está presente, sube el resultado a Google Sheets
        - spreadsheet_id: ID de la hoja de cálculo
        - worksheet_name: Nombre de la hoja de trabajo
    
    Returns:
        Archivo Excel procesado o JSON con información del procesamiento
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
        file_content = file.read()
        filename = secure_filename(file.filename)
        print(f"[PROCESS] File size: {len(file_content)} bytes")
        sys.stdout.flush()
        
        # Obtener credenciales para el procesamiento y los uploads
        credentials, project_id = get_credentials()
        
        # Procesar el archivo
        print(f"[PROCESS] Processing file: {filename}")
        sys.stdout.flush()
        processed_content = venezuela.process_excel_file(file_content, filename, credentials)
        print(f"[PROCESS] File processed successfully. Output size: {len(processed_content)} bytes")
        sys.stdout.flush()
        
        # Obtener parámetros opcionales
        upload_bigquery = request.args.get('upload_bigquery', 'false').lower() == 'true'
        upload_storage = request.args.get('upload_storage', 'false').lower() == 'true'
        upload_sheets = request.args.get('upload_sheets', 'false').lower() == 'true'
        
        print(f"[PROCESS] Upload options - BigQuery: {upload_bigquery}, Storage: {upload_storage}, Sheets: {upload_sheets}")
        sys.stdout.flush()
        
        response_data = {
            'success': True,
            'message': 'File processed successfully',
            'filename': filename,
            'uploads': {}
        }
        
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
        
        # Subir a Cloud Storage si se solicita
        if upload_storage:
            print("[PROCESS] Uploading to Cloud Storage...")
            sys.stdout.flush()
            bucket_name = request.args.get('bucket_name')
            blob_name = request.args.get('blob_name', filename)
            if bucket_name:
                success = venezuela.upload_to_storage(
                    processed_content, credentials, project_id, bucket_name, blob_name
                )
                response_data['uploads']['storage'] = {
                    'success': success,
                    'bucket': bucket_name,
                    'blob': blob_name
                }
                print(f"[PROCESS] Cloud Storage upload result: {success}")
                sys.stdout.flush()
            else:
                print("[PROCESS] Cloud Storage upload failed: missing bucket_name")
                sys.stdout.flush()
                response_data['uploads']['storage'] = {
                    'success': False,
                    'message': 'bucket_name is required'
                }
        
        # Subir a Google Sheets si se solicita
        if upload_sheets:
            print("[PROCESS] Uploading to Google Sheets...")
            sys.stdout.flush()
            spreadsheet_id = request.args.get('spreadsheet_id')
            worksheet_name = request.args.get('worksheet_name', 'Sheet1')
            if spreadsheet_id:
                import pandas as pd
                df = pd.read_excel(io.BytesIO(processed_content))
                success = venezuela.upload_to_sheets(
                    df, credentials, spreadsheet_id, worksheet_name
                )
                response_data['uploads']['sheets'] = {
                    'success': success,
                    'spreadsheet_id': spreadsheet_id,
                    'worksheet': worksheet_name
                }
                print(f"[PROCESS] Google Sheets upload result: {success}")
                sys.stdout.flush()
            else:
                print("[PROCESS] Google Sheets upload failed: missing spreadsheet_id")
                sys.stdout.flush()
                response_data['uploads']['sheets'] = {
                    'success': False,
                    'message': 'spreadsheet_id is required'
                }
        
        # Si no se solicita ninguna subida, devolver el archivo procesado
        if not (upload_bigquery or upload_storage or upload_sheets):
            output_filename = f"processed_{filename}"
            print(f"[PROCESS] Returning processed file: {output_filename}")
            sys.stdout.flush()
            return send_file(
                io.BytesIO(processed_content),
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=output_filename
            )
        
        # Si se solicitó alguna subida, devolver JSON con la información
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


if __name__ == '__main__':
    port = int(os.getenv('PORT', 8750))
    print(f"Starting Flask server on port {port}")
    print("=" * 50)
    sys.stdout.flush()
    app.run(host='0.0.0.0', port=port, debug=True)
