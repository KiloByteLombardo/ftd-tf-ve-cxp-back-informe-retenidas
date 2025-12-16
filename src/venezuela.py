import os
import sys
import io
import pandas as pd
from google.cloud import bigquery, storage
import gspread
from typing import Tuple


def get_provider_mapping(credentials, spreadsheet_id: str, worksheet_name: str = 'Sheet1') -> dict:
    """
    Lee un Google Sheets y crea un diccionario de pareo entre NOMBRE PROVEEDOR y UNIDAD DE NEGOCIO.
    
    Args:
        credentials: Credenciales de GCP
        spreadsheet_id: ID del Google Sheets
        worksheet_name: Nombre de la hoja de trabajo (default: 'Sheet1')
        
    Returns:
        dict: Diccionario con NOMBRE PROVEEDOR como clave y UNIDAD DE NEGOCIO como valor
    """
    try:
        print(f"[VENZUELA] Reading provider mapping from Google Sheets: {spreadsheet_id}/{worksheet_name}")
        sys.stdout.flush()
        
        gspread_client = gspread.authorize(credentials)
        spreadsheet = gspread_client.open_by_key(spreadsheet_id)
        worksheet = spreadsheet.worksheet(worksheet_name)
        
        # Obtener todos los valores de la hoja
        all_values = worksheet.get_all_values()
        
        if not all_values or len(all_values) < 2:
            print(f"[VENZUELA] Warning: Google Sheets is empty or has no data rows")
            sys.stdout.flush()
            return {}
        
        # La primera fila son los encabezados
        headers = [h.strip().upper() for h in all_values[0]]
        
        # Buscar los índices de las columnas
        if 'NOMBRE PROVEEDOR' not in headers:
            print(f"[VENZUELA] Error: Column 'NOMBRE PROVEEDOR' not found in Google Sheets. Headers: {headers}")
            sys.stdout.flush()
            return {}
        
        if 'UNIDAD DE NEGOCIO' not in headers:
            print(f"[VENZUELA] Error: Column 'UNIDAD DE NEGOCIO' not found in Google Sheets. Headers: {headers}")
            sys.stdout.flush()
            return {}
        
        provider_idx = headers.index('NOMBRE PROVEEDOR')
        unidad_idx = headers.index('UNIDAD DE NEGOCIO')
        
        # Crear el diccionario de pareo (normalizar a mayúsculas para comparación)
        mapping = {}
        for row in all_values[1:]:  # Saltar la fila de encabezados
            if len(row) > max(provider_idx, unidad_idx):
                provider = str(row[provider_idx]).strip() if row[provider_idx] else ''
                unidad = str(row[unidad_idx]).strip() if row[unidad_idx] else ''
                if provider:  # Solo agregar si hay un nombre de proveedor
                    # Usar el nombre original del proveedor como clave (sin normalizar)
                    mapping[provider] = unidad
        
        print(f"[VENZUELA] Loaded {len(mapping)} provider mappings from Google Sheets")
        sys.stdout.flush()
        return mapping
        
    except Exception as e:
        print(f"[VENZUELA] Error reading provider mapping from Google Sheets: {str(e)}")
        sys.stdout.flush()
        return {}


def process_excel_file(file_content: bytes, filename: str, credentials=None) -> bytes:
    """
    Procesa un archivo Excel: lo carga en DataFrame, procesa y devuelve como Excel.
    
    Args:
        file_content: Contenido del archivo Excel en bytes
        filename: Nombre del archivo original
        credentials: Credenciales de GCP (opcional, necesario para pareo con Google Sheets)
        
    Returns:
        bytes: Contenido del archivo Excel procesado
    """
    try:
        # Leer el archivo Excel en un DataFrame
        print(f"[VENZUELA] Reading Excel file: {filename}")
        sys.stdout.flush()
        df = pd.read_excel(io.BytesIO(file_content))
        
        print(f"[VENZUELA] DataFrame shape: {df.shape}")
        print(f"[VENZUELA] Columns: {list(df.columns)}")
        sys.stdout.flush()
        
        # Procesar el DataFrame
        print(f"[VENZUELA] Processing dataframe...")
        sys.stdout.flush()
        df_processed = process_dataframe(df, credentials)
        
        # Convertir el DataFrame procesado de vuelta a Excel
        print(f"[VENZUELA] Converting to Excel...")
        sys.stdout.flush()
        output = io.BytesIO()
        df_processed.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        
        print(f"[VENZUELA] Excel file processed successfully. Output shape: {df_processed.shape}")
        sys.stdout.flush()
        return output.getvalue()
        
    except Exception as e:
        print(f"[VENZUELA] Error processing Excel file: {str(e)}")
        sys.stdout.flush()
        raise


def remove_empty_rows(df: pd.DataFrame) -> pd.DataFrame:
    """
    Elimina filas completamente vacías del DataFrame.
    
    Args:
        df: DataFrame original
        
    Returns:
        pd.DataFrame: DataFrame sin filas vacías
    """
    initial_rows = len(df)
    df_processed = df.dropna(how='all')
    removed = initial_rows - len(df_processed)
    
    print(f"[VENZUELA] Removed {removed} empty rows (from {initial_rows} to {len(df_processed)})")
    sys.stdout.flush()
    
    return df_processed


def remove_ndint_invoices(df: pd.DataFrame) -> pd.DataFrame:
    """
    Elimina filas donde "Número Factura" tenga el prefijo "NDINT".
    
    Args:
        df: DataFrame original
        
    Returns:
        pd.DataFrame: DataFrame sin filas con prefijo NDINT
    """
    if 'Número Factura' not in df.columns:
        print(f"[VENZUELA] Warning: Column 'Número Factura' not found. Available columns: {list(df.columns)}")
        sys.stdout.flush()
        return df
    
    initial_rows = len(df)
    
    # Convertir la columna a string para poder hacer el filtro, manejando NaN
    df_processed = df.copy()
    df_processed['Número Factura'] = df_processed['Número Factura'].astype(str)
    
    # Contar cuántas filas tienen el prefijo NDINT antes de eliminarlas
    rows_with_ndint = df_processed['Número Factura'].str.startswith('NDINT', na=False).sum()
    
    # Filtrar: mantener solo las filas que NO empiezan con NDINT
    df_processed = df_processed[~df_processed['Número Factura'].str.startswith('NDINT', na=False)]
    
    removed = initial_rows - len(df_processed)
    print(f"[VENZUELA] Removed {removed} rows with NDINT prefix (from {initial_rows} to {len(df_processed)})")
    sys.stdout.flush()
    
    return df_processed


def add_unidad_negocio_column(df: pd.DataFrame, credentials=None) -> pd.DataFrame:
    """
    Crea la columna "Unidad de Negocio" haciendo pareo con Google Sheets.
    Hace pareo entre la columna "Sucursal" y "NOMBRE PROVEEDOR" del Google Sheets.
    
    Args:
        df: DataFrame original
        credentials: Credenciales de GCP (opcional, necesario para pareo con Google Sheets)
        
    Returns:
        pd.DataFrame: DataFrame con la columna "Unidad de Negocio" agregada
    """
    df_processed = df.copy()
    
    # Verificar que exista la columna Sucursal
    if 'Sucursal' not in df_processed.columns:
        print(f"[VENZUELA] Warning: Column 'Sucursal' not found. Cannot create 'Unidad de Negocio' column")
        sys.stdout.flush()
        df_processed['Unidad de Negocio'] = ''
        return df_processed
    
    # Verificar que se proporcionen credenciales
    if not credentials:
        print(f"[VENZUELA] Warning: No credentials provided. Cannot create 'Unidad de Negocio' column")
        sys.stdout.flush()
        df_processed['Unidad de Negocio'] = ''
        return df_processed
    
    # Obtener el ID del Google Sheets desde variables de entorno
    spreadsheet_id = os.getenv('SHEETS_PROVIDER_MAPPING_ID')
    if not spreadsheet_id:
        print(f"[VENZUELA] Warning: SHEETS_PROVIDER_MAPPING_ID not found in environment variables")
        sys.stdout.flush()
        df_processed['Unidad de Negocio'] = ''
        return df_processed
    
    print(f"[VENZUELA] Creating 'Unidad de Negocio' column using Google Sheets mapping...")
    sys.stdout.flush()
    
    # Obtener el mapeo de proveedores desde Google Sheets
    provider_mapping = get_provider_mapping(credentials, spreadsheet_id)
    
    if not provider_mapping:
        print(f"[VENZUELA] Warning: Could not load provider mapping from Google Sheets")
        sys.stdout.flush()
        df_processed['Unidad de Negocio'] = ''
        return df_processed
    
    # Inicializar la nueva columna con valores vacíos
    df_processed['Unidad de Negocio'] = ''
    
    # Convertir Sucursal a string para hacer el pareo
    df_processed['Sucursal'] = df_processed['Sucursal'].astype(str)
    
    # Hacer el pareo: buscar cada valor de Sucursal en el diccionario
    # El pareo es exacto (case-sensitive) pero con espacios eliminados
    matched_count = 0
    for idx, sucursal in df_processed['Sucursal'].items():
        sucursal_clean = str(sucursal).strip()
        # Buscar coincidencia exacta
        if sucursal_clean in provider_mapping:
            df_processed.at[idx, 'Unidad de Negocio'] = provider_mapping[sucursal_clean]
            matched_count += 1
    
    print(f"[VENZUELA] Matched {matched_count} out of {len(df_processed)} rows with provider mapping")
    if matched_count < len(df_processed):
        unmatched = len(df_processed) - matched_count
        print(f"[VENZUELA] Warning: {unmatched} rows could not be matched with provider mapping")
    sys.stdout.flush()
    
    return df_processed


def process_dataframe(df: pd.DataFrame, credentials=None) -> pd.DataFrame:
    """
    Procesa el DataFrame según la lógica de negocio para archivos R011.
    Aplica los filtros y transformaciones en orden.
    
    Limpiezas aplicadas (en orden):
    1. Eliminar filas completamente vacías
    2. Eliminar filas donde "Número Factura" tenga el prefijo "NDINT"
    3. Crear columna "Unidad de Negocio" haciendo pareo con Google Sheets
    
    Args:
        df: DataFrame original
        credentials: Credenciales de GCP (opcional, necesario para pareo con Google Sheets)
        
    Returns:
        pd.DataFrame: DataFrame procesado
    """
    # Crear una copia para no modificar el original
    df_processed = df.copy()
    
    initial_rows = len(df_processed)
    print(f"[VENZUELA] Starting dataframe processing. Initial rows: {initial_rows}")
    sys.stdout.flush()
    
    # Aplicar filtros en orden
    # 1. Eliminar filas completamente vacías
    df_processed = remove_empty_rows(df_processed)
    
    # 2. Eliminar filas donde "Número Factura" tenga el prefijo "NDINT"
    df_processed = remove_ndint_invoices(df_processed)
    
    # 3. Crear columna "Unidad de Negocio" haciendo pareo con Google Sheets
    df_processed = add_unidad_negocio_column(df_processed, credentials)
    
    final_rows = len(df_processed)
    print(f"[VENZUELA] Processing completed. Final rows: {final_rows} (removed {initial_rows - final_rows} total)")
    sys.stdout.flush()
    
    return df_processed


def upload_to_bigquery(df: pd.DataFrame, credentials, project_id: str, 
                       dataset_id: str, table_id: str, 
                       write_disposition: str = 'WRITE_TRUNCATE') -> bool:
    """
    Sube un DataFrame a BigQuery.
    
    Args:
        df: DataFrame a subir
        credentials: Credenciales de GCP
        project_id: ID del proyecto de GCP
        dataset_id: ID del dataset en BigQuery
        table_id: ID de la tabla en BigQuery
        write_disposition: Modo de escritura ('WRITE_TRUNCATE', 'WRITE_APPEND', 'WRITE_EMPTY')
        
    Returns:
        bool: True si fue exitoso, False en caso contrario
    """
    try:
        bigquery_client = bigquery.Client(credentials=credentials, project=project_id)
        table_ref = bigquery_client.dataset(dataset_id).table(table_id)
        job_config = bigquery.LoadJobConfig(
            write_disposition=write_disposition,
            autodetect=True
        )
        
        print(f"[VENZUELA] Uploading {len(df)} rows to BigQuery: {dataset_id}.{table_id}")
        sys.stdout.flush()
        job = bigquery_client.load_table_from_dataframe(df, table_ref, job_config=job_config)
        job.result()  # Esperar a que termine el job
        
        print(f"[VENZUELA] DataFrame uploaded to BigQuery: {dataset_id}.{table_id}")
        sys.stdout.flush()
        return True
        
    except Exception as e:
        print(f"[VENZUELA] Error uploading to BigQuery: {str(e)}")
        sys.stdout.flush()
        return False


def upload_to_storage(file_content: bytes, credentials, project_id: str,
                     bucket_name: str, blob_name: str) -> bool:
    """
    Sube un archivo a Cloud Storage.
    
    Args:
        file_content: Contenido del archivo en bytes
        credentials: Credenciales de GCP
        project_id: ID del proyecto de GCP
        bucket_name: Nombre del bucket
        blob_name: Nombre del blob (archivo) en el bucket
        
    Returns:
        bool: True si fue exitoso, False en caso contrario
    """
    try:
        storage_client = storage.Client(credentials=credentials, project=project_id)
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        print(f"[VENZUELA] Uploading file to Cloud Storage: gs://{bucket_name}/{blob_name}")
        sys.stdout.flush()
        blob.upload_from_string(
            file_content, 
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
        print(f"[VENZUELA] File uploaded to Cloud Storage: gs://{bucket_name}/{blob_name}")
        sys.stdout.flush()
        return True
        
    except Exception as e:
        print(f"[VENZUELA] Error uploading to Cloud Storage: {str(e)}")
        sys.stdout.flush()
        return False


def upload_to_sheets(df: pd.DataFrame, credentials, spreadsheet_id: str, 
                    worksheet_name: str = 'Sheet1', clear: bool = True) -> bool:
    """
    Sube un DataFrame a Google Sheets.
    
    Args:
        df: DataFrame a subir
        credentials: Credenciales de GCP
        spreadsheet_id: ID de la hoja de cálculo
        worksheet_name: Nombre de la hoja de trabajo
        clear: Si True, limpia la hoja antes de escribir
        
    Returns:
        bool: True si fue exitoso, False en caso contrario
    """
    try:
        gspread_client = gspread.authorize(credentials)
        spreadsheet = gspread_client.open_by_key(spreadsheet_id)
        
        try:
            worksheet = spreadsheet.worksheet(worksheet_name)
        except gspread.exceptions.WorksheetNotFound:
            worksheet = spreadsheet.add_worksheet(title=worksheet_name, rows=1000, cols=26)
        
        if clear:
            worksheet.clear()
        
        # Actualizar la hoja con los datos del DataFrame
        print(f"[VENZUELA] Uploading {len(df)} rows to Google Sheets: {spreadsheet_id}/{worksheet_name}")
        sys.stdout.flush()
        worksheet.update([df.columns.values.tolist()] + df.values.tolist())
        
        print(f"[VENZUELA] DataFrame uploaded to Google Sheets: {spreadsheet_id}/{worksheet_name}")
        sys.stdout.flush()
        return True
        
    except Exception as e:
        print(f"[VENZUELA] Error uploading to Google Sheets: {str(e)}")
        sys.stdout.flush()
        return False
