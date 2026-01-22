"""
driveSearch.py - Módulo para búsqueda de archivos en Google Drive y endpoint SuperApp

Este módulo contiene las funciones para:
- Buscar archivos en carpetas normales de Google Drive
- Buscar archivos en Shared Drives (Unidades Compartidas) con OCR
- Buscar PDFs en el endpoint de SuperApp

Configuración mediante variables de entorno:
- DRIVE_FOLDER_1 a DRIVE_FOLDER_5: IDs de carpetas/Shared Drives
- DRIVE_FOLDER_X_IS_SHARED: true/false para indicar si es Shared Drive
- SUPER_APP_API_URL: URL del endpoint de SuperApp
- SUPER_APP_API_KEY: API key para SuperApp
- DRIVE_MAX_THREADS: Número máximo de threads (default: 5)
- DRIVE_BATCH_SIZE: Tamaño del lote por thread (default: 100)
"""

import os
import sys
import time
import json
import requests
from typing import Optional, List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


class DriveSearcher:
    """
    Clase para buscar archivos en Google Drive y SuperApp.
    Soporta búsqueda en carpetas normales y Shared Drives con OCR.
    """
    
    def __init__(self, credentials, folders: List[str] = None, shared_drive_flags: List[bool] = None):
        """
        Inicializa el buscador de Drive.
        
        Args:
            credentials: Credenciales de Google
            folders: Lista de IDs de carpetas/Shared Drives (opcional, se puede cargar desde env)
            shared_drive_flags: Lista de flags indicando si cada carpeta es Shared Drive
        """
        self.credentials = credentials
        
        # Cargar folders y flags desde env, manteniendo el mapeo correcto
        if folders is None or shared_drive_flags is None:
            self.folders, self.shared_drive_flags = self._load_folders_and_flags_from_env()
        else:
            self.folders = folders
            self.shared_drive_flags = shared_drive_flags
        
        # Configuración de SuperApp
        self.superapp_url = os.getenv('SUPER_APP_API_URL')
        self.superapp_api_key = os.getenv('SUPER_APP_API_KEY')
        
        # Configuración de procesamiento
        self.max_threads = self._get_env_int('DRIVE_MAX_THREADS', 5)
        self.batch_size = self._get_env_int('DRIVE_BATCH_SIZE', 100)
        
        # Log de configuración
        self._log_configuration()
    
    def _log_configuration(self):
        """Muestra la configuración actual para debug."""
        print(f"[DRIVE_SEARCH] === Configuration ===")
        print(f"[DRIVE_SEARCH] Folders configured: {len(self.folders)}")
        for i, (folder, is_shared) in enumerate(zip(self.folders, self.shared_drive_flags)):
            folder_type = "Shared Drive" if is_shared else "Regular Folder"
            print(f"[DRIVE_SEARCH]   [{i+1}] {folder[:25]}... ({folder_type})")
        print(f"[DRIVE_SEARCH] SuperApp URL: {'Configured' if self.superapp_url else 'Not configured'}")
        print(f"[DRIVE_SEARCH] Max threads: {self.max_threads}, Batch size: {self.batch_size}")
        sys.stdout.flush()
    
    def _get_env_int(self, key: str, default: int) -> int:
        """Obtiene un entero de una variable de entorno."""
        value = os.getenv(key)
        if value:
            try:
                return int(value)
            except:
                pass
        return default
    
    def _load_folders_and_flags_from_env(self) -> Tuple[List[str], List[bool]]:
        """
        Carga los IDs de carpetas y sus flags desde variables de entorno.
        
        IMPORTANTE: Mantiene la correspondencia 1:1 entre folders y flags.
        Solo incluye en las listas los folders que están definidos.
        
        Returns:
            Tuple[List[str], List[bool]]: (folders, shared_flags) con la misma longitud
        """
        folders = []
        flags = []
        
        for i in range(1, 6):
            folder_id = os.getenv(f'DRIVE_FOLDER_{i}')
            if folder_id and folder_id.strip():
                folders.append(folder_id.strip())
                # Obtener el flag correspondiente a ESTE folder
                is_shared_env = os.getenv(f'DRIVE_FOLDER_{i}_IS_SHARED', 'false').lower()
                is_shared = is_shared_env in ['true', '1', 'yes']
                flags.append(is_shared)
                print(f"[DRIVE_SEARCH] Loaded DRIVE_FOLDER_{i}: {folder_id.strip()[:25]}... (is_shared={is_shared})")
        
        if not folders:
            print(f"[DRIVE_SEARCH] WARNING: No Drive folders configured!")
        
        sys.stdout.flush()
        return folders, flags
    
    def create_drive_service(self):
        """
        Crea una nueva instancia del servicio de Drive (thread-safe).
        Asegura que las credenciales tengan los scopes necesarios.
        """
        try:
            # Asegurar que las credenciales tengan los scopes necesarios para Drive
            credentials_to_use = self.credentials
            
            drive_scopes = [
                'https://www.googleapis.com/auth/drive.readonly',
                'https://www.googleapis.com/auth/drive.metadata.readonly'
            ]
            
            # Si las credenciales soportan scopes y no los tienen, agregarlos
            if hasattr(self.credentials, 'with_scopes'):
                try:
                    credentials_to_use = self.credentials.with_scopes(drive_scopes)
                except Exception as e:
                    # Si ya tiene scopes o no se pueden agregar, usar las originales
                    print(f"[DRIVE_SEARCH] Note: Using original credentials ({str(e)[:50]})")
                    credentials_to_use = self.credentials
            elif isinstance(self.credentials, service_account.Credentials):
                try:
                    credentials_to_use = self.credentials.with_scopes(drive_scopes)
                except Exception:
                    credentials_to_use = self.credentials
            
            service = build('drive', 'v3', credentials=credentials_to_use, cache_discovery=False)
            return service
            
        except Exception as e:
            print(f"[DRIVE_SEARCH] ERROR creating Drive service: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            return None
    
    def search_file_in_folder(self, drive_service, folder_id: str, search_term: str) -> Optional[str]:
        """
        Busca un archivo en una carpeta normal de Google Drive por nombre.
        
        Args:
            drive_service: Instancia del servicio de Drive
            folder_id: ID de la carpeta de Google Drive
            search_term: Término de búsqueda (número de OC)
            
        Returns:
            str: ID del archivo encontrado, o None si no se encuentra
        """
        if not drive_service:
            print(f"[DRIVE_SEARCH] ERROR: No drive_service for folder search")
            return None
            
        try:
            search_term_escaped = search_term.replace("'", "\\'")
            query = f"'{folder_id}' in parents and name contains '{search_term_escaped}' and trashed=false"
            
            start_time = time.time()
            
            results = drive_service.files().list(
                q=query,
                fields="files(id, name, mimeType)",
                pageSize=10,
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            ).execute()
            
            elapsed_time = time.time() - start_time
            
            items = results.get('files', [])
            
            if items:
                file_id = items[0]['id']
                file_name = items[0]['name']
                print(f"[DRIVE_SEARCH] FOUND in folder {folder_id[:15]}...: {file_name} ({elapsed_time:.2f}s)")
                sys.stdout.flush()
                return file_id
            
            return None
            
        except HttpError as error:
            error_code = error.resp.status if hasattr(error, 'resp') else 'unknown'
            error_reason = error._get_reason() if hasattr(error, '_get_reason') else str(error)
            print(f"[DRIVE_SEARCH] HTTP Error {error_code} in folder {folder_id[:15]}... for '{search_term}': {error_reason}")
            sys.stdout.flush()
            return None
        except Exception as e:
            print(f"[DRIVE_SEARCH] ERROR in folder {folder_id[:15]}... for '{search_term}': {str(e)}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            return None
    
    def search_file_in_shared_drive(self, drive_service, shared_drive_id: str, search_term: str) -> Optional[str]:
        """
        Busca un archivo en una Unidad Compartida (Shared Drive) por contenido OCR del PDF y por nombre.
        
        Args:
            drive_service: Instancia del servicio de Drive
            shared_drive_id: ID de la Unidad Compartida (Shared Drive)
            search_term: Término de búsqueda (número de OC)
            
        Returns:
            str: ID del archivo encontrado, o None si no se encuentra
        """
        if not drive_service:
            print(f"[DRIVE_SEARCH] ERROR: No drive_service for shared drive search")
            return None
            
        try:
            start_time = time.time()
            search_term_escaped = search_term.replace("'", "\\'")
            
            all_items = []
            existing_ids = set()
            
            # Búsqueda 1: Por contenido del PDF (fullText) - Busca en el OCR del PDF
            query_fulltext = f"fullText contains '{search_term_escaped}' and mimeType = 'application/pdf' and trashed = false"
            
            try:
                results = drive_service.files().list(
                    corpora='drive',
                    driveId=shared_drive_id,
                    q=query_fulltext,
                    pageSize=50,
                    fields="files(id, name, webViewLink, parents)",
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True
                ).execute()
                
                for item in results.get('files', []):
                    if item['id'] not in existing_ids:
                        all_items.append(item)
                        existing_ids.add(item['id'])
                        
            except HttpError as e:
                error_code = e.resp.status if hasattr(e, 'resp') else 'unknown'
                print(f"[DRIVE_SEARCH] fullText search failed ({error_code}), trying name search...")
                sys.stdout.flush()
            
            # Búsqueda 2: Por nombre del archivo
            query_name = f"name contains '{search_term_escaped}' and trashed = false"
            
            try:
                results2 = drive_service.files().list(
                    corpora='drive',
                    driveId=shared_drive_id,
                    q=query_name,
                    pageSize=50,
                    fields="files(id, name, webViewLink, parents)",
                    supportsAllDrives=True,
                    includeItemsFromAllDrives=True
                ).execute()
                
                for item in results2.get('files', []):
                    if item['id'] not in existing_ids:
                        all_items.append(item)
                        existing_ids.add(item['id'])
                        
            except HttpError as e:
                error_code = e.resp.status if hasattr(e, 'resp') else 'unknown'
                print(f"[DRIVE_SEARCH] name search failed ({error_code}) for '{search_term}'")
                sys.stdout.flush()
            
            elapsed_time = time.time() - start_time
            
            if all_items:
                file_id = all_items[0]['id']
                file_name = all_items[0]['name']
                print(f"[DRIVE_SEARCH] FOUND in Shared Drive {shared_drive_id[:15]}...: {file_name} ({elapsed_time:.2f}s, {len(all_items)} results)")
                sys.stdout.flush()
                return file_id
            
            return None
            
        except HttpError as error:
            error_code = error.resp.status if hasattr(error, 'resp') else 'unknown'
            error_reason = error._get_reason() if hasattr(error, '_get_reason') else str(error)
            print(f"[DRIVE_SEARCH] HTTP Error {error_code} in Shared Drive {shared_drive_id[:15]}... for '{search_term}': {error_reason}")
            sys.stdout.flush()
            return None
        except Exception as e:
            print(f"[DRIVE_SEARCH] ERROR in Shared Drive {shared_drive_id[:15]}... for '{search_term}': {str(e)}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            return None
    
    def search_in_superapp(self, orden_compra: str, verbose: bool = False) -> Optional[str]:
        """
        Busca el PDF de la factura en el endpoint de SuperApp.
        
        Args:
            orden_compra: Número de orden de compra
            verbose: Si es True, muestra logs detallados de cada búsqueda
            
        Returns:
            str: URL del invoicePDF si se encuentra, o None
        """
        if not self.superapp_url or not self.superapp_api_key:
            return None
        
        try:
            request_url = f"{self.superapp_url}?order={orden_compra}"
            
            headers = {
                'x-api-key': self.superapp_api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.get(request_url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                # Buscar el campo invoicePdf en la respuesta
                if isinstance(data, dict) and 'invoicePdf' in data:
                    invoice_pdf = data.get('invoicePdf')
                    if invoice_pdf:
                        print(f"[SUPERAPP] FOUND invoicePdf for OC '{orden_compra}'")
                        sys.stdout.flush()
                        return invoice_pdf
                
                # Si la respuesta es una lista, buscar en el primer elemento
                if isinstance(data, list) and len(data) > 0:
                    first_item = data[0]
                    if isinstance(first_item, dict) and 'invoicePdf' in first_item:
                        invoice_pdf = first_item.get('invoicePdf')
                        if invoice_pdf:
                            print(f"[SUPERAPP] FOUND invoicePdf for OC '{orden_compra}'")
                            sys.stdout.flush()
                            return invoice_pdf
                
                # Si llegamos aquí, la respuesta fue 200 pero no tiene invoicePdf
                if verbose:
                    print(f"[SUPERAPP] No invoicePdf in response for OC '{orden_compra}' (status 200)")
                    sys.stdout.flush()
                    
            elif response.status_code == 404:
                # 404 es esperado cuando no existe
                if verbose:
                    print(f"[SUPERAPP] Not found (404) for OC '{orden_compra}'")
                    sys.stdout.flush()
            else:
                # Otros códigos de error
                print(f"[SUPERAPP] Error {response.status_code} for OC '{orden_compra}'")
                sys.stdout.flush()
            
            return None
            
        except requests.exceptions.Timeout:
            print(f"[SUPERAPP] Timeout for OC '{orden_compra}'")
            sys.stdout.flush()
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"[SUPERAPP] Connection error for OC '{orden_compra}': {str(e)[:50]}")
            sys.stdout.flush()
            return None
        except Exception as e:
            print(f"[SUPERAPP] Error for OC '{orden_compra}': {str(e)}")
            sys.stdout.flush()
            return None
    
    def search_for_order(self, drive_service, orden_compra: str) -> Dict[str, Any]:
        """
        Busca archivos para una orden de compra en todas las fuentes.
        
        Args:
            drive_service: Instancia del servicio de Drive
            orden_compra: Número de orden de compra
            
        Returns:
            dict: Diccionario con los resultados de la búsqueda
        """
        links_data = {
            "orden_compra": orden_compra,
            "drive_files": [],
            "invoice_pdf": None
        }
        
        # Buscar en TODAS las carpetas de Drive
        for folder_idx, folder_id in enumerate(self.folders):
            if not folder_id or folder_id.strip() == '':
                continue
            
            try:
                # Obtener el flag correspondiente a este folder
                is_shared_drive = self.shared_drive_flags[folder_idx] if folder_idx < len(self.shared_drive_flags) else False
                
                if is_shared_drive:
                    file_id = self.search_file_in_shared_drive(drive_service, folder_id.strip(), orden_compra)
                else:
                    file_id = self.search_file_in_folder(drive_service, folder_id.strip(), orden_compra)
                
                if file_id:
                    preview_link = f"https://drive.google.com/file/d/{file_id}/preview"
                    links_data["drive_files"].append({
                        "file_id": file_id,
                        "preview_link": preview_link,
                        "folder_number": folder_idx + 1,
                        "source": "shared_drive" if is_shared_drive else "folder"
                    })
            except Exception as e:
                print(f"[DRIVE_SEARCH] Error searching folder {folder_idx + 1} for OC '{orden_compra}': {str(e)}")
                sys.stdout.flush()
                continue
        
        # Buscar en el endpoint de SuperApp (si está configurado)
        if self.superapp_url and self.superapp_api_key:
            try:
                invoice_pdf = self.search_in_superapp(orden_compra)
                if invoice_pdf:
                    links_data["invoice_pdf"] = invoice_pdf
            except Exception as e:
                print(f"[SUPERAPP] Error for OC '{orden_compra}': {str(e)}")
                sys.stdout.flush()
        
        return links_data
    
    def process_batch(self, batch_data: tuple) -> Dict[int, str]:
        """
        Procesa un lote de facturas buscando archivos.
        
        Args:
            batch_data: Tupla (thread_name, batch) donde batch es lista de (idx, orden_compra)
            
        Returns:
            dict: Diccionario {idx: json_string}
        """
        thread_name, batch = batch_data
        import threading
        threading.current_thread().name = thread_name
        
        # Crear una instancia del servicio de Drive para este thread
        drive_service = self.create_drive_service()
        if not drive_service:
            print(f"[{thread_name}] ERROR: Could not create Drive service - skipping batch")
            sys.stdout.flush()
            # Retornar JSON vacío para todas las filas del batch
            return {idx: '{}' for idx, _ in batch}
        
        print(f"[{thread_name}] Started processing batch of {len(batch)} invoices")
        sys.stdout.flush()
        
        batch_results = {}
        batch_matched = 0
        batch_errors = 0
        
        for idx, orden_compra in batch:
            try:
                links_data = self.search_for_order(drive_service, orden_compra)
                
                has_drive_files = len(links_data["drive_files"]) > 0
                has_invoice_pdf = links_data["invoice_pdf"] is not None
                
                if has_drive_files or has_invoice_pdf:
                    batch_results[idx] = json.dumps(links_data, ensure_ascii=False)
                    batch_matched += 1
                else:
                    batch_results[idx] = '{}'
            except Exception as e:
                print(f"[{thread_name}] Error processing OC '{orden_compra}': {str(e)}")
                sys.stdout.flush()
                batch_results[idx] = '{}'
                batch_errors += 1
        
        print(f"[{thread_name}] Completed: {batch_matched}/{len(batch)} files found, {batch_errors} errors")
        sys.stdout.flush()
        return batch_results
    
    def search_all(self, rows_to_process: List[tuple]) -> Dict[int, str]:
        """
        Busca archivos para todas las filas en paralelo.
        
        Args:
            rows_to_process: Lista de tuplas (idx, orden_compra)
            
        Returns:
            dict: Diccionario {idx: json_string} con los resultados
        """
        if not rows_to_process:
            print("[DRIVE_SEARCH] No rows to process")
            return {}
        
        if not self.folders:
            print("[DRIVE_SEARCH] ERROR: No folders configured - cannot search")
            return {idx: '{}' for idx, _ in rows_to_process}
        
        total_rows = len(rows_to_process)
        print(f"[DRIVE_SEARCH] ========================================")
        print(f"[DRIVE_SEARCH] Starting search for {total_rows} orders")
        print(f"[DRIVE_SEARCH] ========================================")
        sys.stdout.flush()
        
        # Dividir en lotes
        batches = []
        for i in range(0, len(rows_to_process), self.batch_size):
            batches.append(rows_to_process[i:i + self.batch_size])
        
        print(f"[DRIVE_SEARCH] Created {len(batches)} batches of up to {self.batch_size} invoices each")
        sys.stdout.flush()
        
        # Preparar lotes con nombres de threads
        batch_tasks = []
        for i, batch in enumerate(batches, 1):
            thread_name = f"Thread-Drive_{i}"
            batch_tasks.append((thread_name, batch))
        
        # Procesar en paralelo
        max_threads = min(self.max_threads, len(batches))
        print(f"[DRIVE_SEARCH] Using {max_threads} parallel threads")
        sys.stdout.flush()
        
        results_dict = {}
        processed_count = 0
        matched_count = 0
        count_lock = Lock()
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_batch = {executor.submit(self.process_batch, task): task for task in batch_tasks}
            
            for future in as_completed(future_to_batch):
                batch_task = future_to_batch[future]
                try:
                    batch_results = future.result()
                    
                    with count_lock:
                        processed_count += len(batch_results)
                        matched_in_batch = sum(1 for v in batch_results.values() if v != '{}')
                        matched_count += matched_in_batch
                        
                        print(f"[DRIVE_SEARCH] Progress: {processed_count}/{total_rows} rows processed, {matched_count} files found")
                        sys.stdout.flush()
                    
                    results_dict.update(batch_results)
                    
                except Exception as e:
                    print(f"[DRIVE_SEARCH] ERROR processing batch: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    sys.stdout.flush()
                    
                    # Asignar JSON vacío a todas las filas del batch que falló
                    for idx, _ in batch_task[1]:
                        results_dict[idx] = '{}'
        
        # Calcular estadísticas detalladas
        drive_count = 0
        superapp_count = 0
        for json_str in results_dict.values():
            if json_str != '{}':
                try:
                    data = json.loads(json_str)
                    if data.get('drive_files'):
                        drive_count += 1
                    if data.get('invoice_pdf'):
                        superapp_count += 1
                except:
                    pass
        
        print(f"[DRIVE_SEARCH] ========================================")
        print(f"[DRIVE_SEARCH] COMPLETED: {matched_count}/{total_rows} files found total")
        print(f"[DRIVE_SEARCH]   - From Drive folders: {drive_count}")
        print(f"[DRIVE_SEARCH]   - From SuperApp API: {superapp_count}")
        print(f"[DRIVE_SEARCH] ========================================")
        sys.stdout.flush()
        
        return results_dict


def search_drive_links(df, credentials) -> dict:
    """
    Función principal para buscar links de Drive para un DataFrame.
    
    Args:
        df: DataFrame con columna 'Orden Compra'
        credentials: Credenciales de Google
        
    Returns:
        dict: Diccionario {idx: json_string} con los resultados
    """
    print(f"[DRIVE_SEARCH] ========================================")
    print(f"[DRIVE_SEARCH] Starting Drive link search")
    print(f"[DRIVE_SEARCH] DataFrame has {len(df)} rows")
    print(f"[DRIVE_SEARCH] ========================================")
    sys.stdout.flush()
    
    # Verificar que exista la columna Orden Compra
    if 'Orden Compra' not in df.columns:
        print(f"[DRIVE_SEARCH] ERROR: Column 'Orden Compra' not found in DataFrame")
        print(f"[DRIVE_SEARCH] Available columns: {list(df.columns)}")
        sys.stdout.flush()
        return {}
    
    # Preparar datos para procesamiento
    rows_to_process = []
    skipped_count = 0
    
    for idx, row in df.iterrows():
        orden_compra = str(row.get('Orden Compra', '')).strip()
        if orden_compra and orden_compra.lower() not in ['nan', 'none', '']:
            rows_to_process.append((idx, orden_compra))
        else:
            skipped_count += 1
    
    print(f"[DRIVE_SEARCH] Rows to process: {len(rows_to_process)}")
    print(f"[DRIVE_SEARCH] Rows skipped (empty OC): {skipped_count}")
    sys.stdout.flush()
    
    if not rows_to_process:
        print("[DRIVE_SEARCH] No valid rows to process")
        return {}
    
    # Crear buscador y ejecutar
    try:
        searcher = DriveSearcher(credentials)
        return searcher.search_all(rows_to_process)
    except Exception as e:
        print(f"[DRIVE_SEARCH] FATAL ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.stdout.flush()
        return {}
