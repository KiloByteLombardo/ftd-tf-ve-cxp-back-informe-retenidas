"""
Módulo para envío de correos usando Gmail API con OAuth2.
Soporta autenticación con client_secret.json (OAuth2 de usuario).
Busca información de destinatarios en Google Sheets.
"""

import os
import sys
import base64
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional, Dict, List, Tuple, Any
import gspread
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Scopes necesarios para Gmail API y Google Sheets
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.send']
SHEETS_SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']
ALL_SCOPES = GMAIL_SCOPES + SHEETS_SCOPES

# Rutas de archivos de credenciales (configurables por variables de entorno)
CLIENT_SECRET_PATH = os.getenv('GMAIL_CLIENT_SECRET_PATH', '/app/client_secret.json')
TOKEN_PATH = os.getenv('GMAIL_TOKEN_PATH', '/app/gmail_token.json')


def get_gmail_credentials_oauth2(
    client_secret_path: str = None,
    token_path: str = None,
    scopes: List[str] = None
) -> Tuple[Optional[Credentials], Optional[str]]:
    """
    Obtiene credenciales OAuth2 para Gmail desde un token guardado.
    Si el token no existe o está expirado, retorna None para indicar
    que se necesita autorización.
    
    Args:
        client_secret_path: Ruta al archivo client_secret.json
        token_path: Ruta al archivo donde se guarda el token
        scopes: Lista de scopes necesarios (no se usa para validación estricta)
        
    Returns:
        Tuple: (credentials o None, error_message o None)
    """
    client_secret_path = client_secret_path or CLIENT_SECRET_PATH
    token_path = token_path or TOKEN_PATH
    
    creds = None
    
    # Verificar si existe un token guardado
    if os.path.exists(token_path):
        try:
            # Cargar sin especificar scopes para evitar validación estricta
            # Los scopes ya están incluidos en el token
            creds = Credentials.from_authorized_user_file(token_path)
            print(f"[EMAIL] Loaded credentials from {token_path}")
            print(f"[EMAIL] Token scopes: {creds.scopes}")
            sys.stdout.flush()
        except Exception as e:
            print(f"[EMAIL] Error loading token: {str(e)}")
            sys.stdout.flush()
            creds = None
    
    # Si no hay credenciales válidas
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                print("[EMAIL] Refreshing expired token...")
                sys.stdout.flush()
                creds.refresh(Request())
                # Guardar el token actualizado
                save_token(creds, token_path)
                print("[EMAIL] Token refreshed and saved")
                sys.stdout.flush()
            except Exception as e:
                error_msg = f"Error refreshing token: {str(e)}"
                print(f"[EMAIL] {error_msg}")
                sys.stdout.flush()
                return None, error_msg
        else:
            # No hay token válido, se necesita autorización
            return None, "No valid token found. Authorization required."
    
    # Verificar que tenga el scope necesario para enviar correos
    if creds.scopes:
        has_send_scope = any('gmail.send' in scope or 'mail.google.com' in scope for scope in creds.scopes)
        if not has_send_scope:
            return None, f"Token does not have gmail.send scope. Current scopes: {creds.scopes}"
    
    return creds, None


def save_token(creds: Credentials, token_path: str = None):
    """
    Guarda las credenciales OAuth2 en un archivo JSON.
    
    Args:
        creds: Credenciales OAuth2
        token_path: Ruta donde guardar el token
    """
    token_path = token_path or TOKEN_PATH
    
    try:
        # Crear directorio si no existe
        token_dir = os.path.dirname(token_path)
        if token_dir and not os.path.exists(token_dir):
            os.makedirs(token_dir)
        
        with open(token_path, 'w') as token_file:
            token_file.write(creds.to_json())
        
        print(f"[EMAIL] Token saved to {token_path}")
        sys.stdout.flush()
    except Exception as e:
        print(f"[EMAIL] Error saving token: {str(e)}")
        sys.stdout.flush()


def create_oauth2_flow(
    client_secret_path: str = None,
    scopes: List[str] = None,
    redirect_uri: str = None
) -> Tuple[Optional[Flow], Optional[str]]:
    """
    Crea un flujo OAuth2 para autorización.
    
    Args:
        client_secret_path: Ruta al archivo client_secret.json
        scopes: Lista de scopes necesarios
        redirect_uri: URI de redirección (para aplicaciones web)
        
    Returns:
        Tuple: (Flow o None, error_message o None)
    """
    client_secret_path = client_secret_path or CLIENT_SECRET_PATH
    scopes = scopes or GMAIL_SCOPES
    
    if not os.path.exists(client_secret_path):
        error_msg = f"Client secret file not found: {client_secret_path}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        return None, error_msg
    
    try:
        if redirect_uri:
            # Para aplicaciones web con redirect
            flow = Flow.from_client_secrets_file(
                client_secret_path,
                scopes=scopes,
                redirect_uri=redirect_uri
            )
        else:
            # Para aplicaciones de escritorio/servidor
            flow = InstalledAppFlow.from_client_secrets_file(
                client_secret_path,
                scopes=scopes
            )
        
        return flow, None
        
    except Exception as e:
        error_msg = f"Error creating OAuth2 flow: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        return None, error_msg


def get_authorization_url(
    client_secret_path: str = None,
    scopes: List[str] = None,
    redirect_uri: str = None
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Genera la URL de autorización OAuth2.
    
    Args:
        client_secret_path: Ruta al archivo client_secret.json
        scopes: Lista de scopes necesarios
        redirect_uri: URI de redirección
        
    Returns:
        Tuple: (authorization_url, state, error_message)
    """
    client_secret_path = client_secret_path or CLIENT_SECRET_PATH
    scopes = scopes or GMAIL_SCOPES
    
    flow, error = create_oauth2_flow(client_secret_path, scopes, redirect_uri)
    
    if error:
        return None, None, error
    
    try:
        # Generar URL de autorización
        # NO usar include_granted_scopes para evitar que Google devuelva scopes adicionales
        authorization_url, state = flow.authorization_url(
            access_type='offline',  # Para obtener refresh_token
            prompt='consent'  # Forzar consentimiento para obtener refresh_token
        )
        
        print(f"[EMAIL] Authorization URL generated. State: {state}")
        print(f"[EMAIL] Requested scopes: {scopes}")
        sys.stdout.flush()
        
        return authorization_url, state, None
        
    except Exception as e:
        error_msg = f"Error generating authorization URL: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        return None, None, error_msg


def exchange_code_for_token(
    code: str,
    client_secret_path: str = None,
    scopes: List[str] = None,
    redirect_uri: str = None,
    token_path: str = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Intercambia el código de autorización por tokens.
    Hace el intercambio manualmente para evitar problemas con scopes adicionales.
    
    Args:
        code: Código de autorización de Google
        client_secret_path: Ruta al archivo client_secret.json
        scopes: Lista de scopes
        redirect_uri: URI de redirección (debe coincidir con la usada en get_authorization_url)
        token_path: Ruta donde guardar el token
        
    Returns:
        Tuple: (success, result_dict)
    """
    import requests as http_requests
    
    client_secret_path = client_secret_path or CLIENT_SECRET_PATH
    scopes = scopes or GMAIL_SCOPES
    token_path = token_path or TOKEN_PATH
    
    if not os.path.exists(client_secret_path):
        return False, {'error': f"Client secret file not found: {client_secret_path}"}
    
    try:
        # Leer client_secret.json para obtener client_id y client_secret
        with open(client_secret_path, 'r') as f:
            client_config = json.load(f)
        
        # El formato puede ser "installed" o "web"
        if 'installed' in client_config:
            client_info = client_config['installed']
        elif 'web' in client_config:
            client_info = client_config['web']
        else:
            return False, {'error': 'Invalid client_secret.json format'}
        
        client_id = client_info['client_id']
        client_secret = client_info['client_secret']
        token_uri = client_info.get('token_uri', 'https://oauth2.googleapis.com/token')
        
        print(f"[EMAIL] Exchanging code for token...")
        print(f"[EMAIL] Token URI: {token_uri}")
        print(f"[EMAIL] Redirect URI: {redirect_uri}")
        sys.stdout.flush()
        
        # Hacer el intercambio de código por token manualmente
        token_response = http_requests.post(
            token_uri,
            data={
                'code': code,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }
        )
        
        if token_response.status_code != 200:
            error_data = token_response.json()
            error_msg = error_data.get('error_description', error_data.get('error', 'Unknown error'))
            print(f"[EMAIL] Token exchange failed: {error_msg}")
            sys.stdout.flush()
            return False, {'error': f"Token exchange failed: {error_msg}"}
        
        token_data = token_response.json()
        
        print(f"[EMAIL] Token received successfully")
        sys.stdout.flush()
        
        # Crear credenciales desde los datos del token
        creds = Credentials(
            token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token'),
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret,
            scopes=token_data.get('scope', ' '.join(scopes)).split(' ')
        )
        
        # Guardar el token
        save_token(creds, token_path)
        
        # Con scope gmail.send no podemos leer el perfil, así que solo confirmamos el token
        print(f"[EMAIL] Token obtained and saved successfully")
        print(f"[EMAIL] Scopes granted: {creds.scopes}")
        sys.stdout.flush()
        
        return True, {
            'email': 'authorized',  # No podemos obtener el email con solo gmail.send
            'token_saved': True,
            'token_path': token_path,
            'scopes': list(creds.scopes) if creds.scopes else []
        }
        
    except Exception as e:
        error_msg = f"Error exchanging code for token: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return False, {'error': error_msg}


def run_local_authorization(
    client_secret_path: str = None,
    scopes: List[str] = None,
    token_path: str = None,
    port: int = 8080
) -> Tuple[bool, Dict[str, Any]]:
    """
    Ejecuta el flujo de autorización localmente (abre navegador).
    Útil para autorización inicial en desarrollo.
    
    Args:
        client_secret_path: Ruta al archivo client_secret.json
        scopes: Lista de scopes
        token_path: Ruta donde guardar el token
        port: Puerto para el servidor local de callback
        
    Returns:
        Tuple: (success, result_dict)
    """
    client_secret_path = client_secret_path or CLIENT_SECRET_PATH
    scopes = scopes or GMAIL_SCOPES
    token_path = token_path or TOKEN_PATH
    
    if not os.path.exists(client_secret_path):
        return False, {'error': f"Client secret file not found: {client_secret_path}"}
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            client_secret_path,
            scopes=scopes
        )
        
        # Ejecutar servidor local para capturar el callback
        creds = flow.run_local_server(port=port)
        
        # Guardar el token
        save_token(creds, token_path)
        
        # Obtener información del usuario
        service = build('gmail', 'v1', credentials=creds)
        profile = service.users().getProfile(userId='me').execute()
        
        print(f"[EMAIL] Authorization successful for: {profile.get('emailAddress')}")
        sys.stdout.flush()
        
        return True, {
            'email': profile.get('emailAddress'),
            'token_saved': True,
            'token_path': token_path
        }
        
    except Exception as e:
        error_msg = f"Error in local authorization: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        return False, {'error': error_msg}


def get_credentials_with_scopes(credentials, scopes: List[str]):
    """
    Agrega scopes a las credenciales si es necesario.
    
    Args:
        credentials: Credenciales de GCP
        scopes: Lista de scopes a agregar
        
    Returns:
        Credenciales con los scopes necesarios
    """
    # Si son credenciales OAuth2 de usuario, ya tienen los scopes
    if isinstance(credentials, Credentials):
        return credentials
    
    if hasattr(credentials, 'with_scopes'):
        return credentials.with_scopes(scopes)
    elif isinstance(credentials, service_account.Credentials):
        return credentials.with_scopes(scopes)
    return credentials


def search_email_in_sheet(
    credentials,
    spreadsheet_id: str,
    worksheet_name: str,
    search_column: str,
    search_value: str,
    email_column: str,
    additional_columns: Optional[List[str]] = None
) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Busca un valor en una columna de Google Sheets y retorna el correo correspondiente.
    
    Args:
        credentials: Credenciales de GCP (Service Account o OAuth2)
        spreadsheet_id: ID del Google Sheets
        worksheet_name: Nombre de la hoja de trabajo
        search_column: Nombre de la columna donde buscar
        search_value: Valor a buscar
        email_column: Nombre de la columna que contiene el correo
        additional_columns: Lista de columnas adicionales a retornar (opcional)
        
    Returns:
        Tuple: (email encontrado o None, diccionario con columnas adicionales)
    """
    try:
        print(f"[EMAIL] Searching in Google Sheets: {spreadsheet_id}/{worksheet_name}")
        print(f"[EMAIL] Search criteria: {search_column} = '{search_value}'")
        sys.stdout.flush()
        
        # Obtener credenciales con scope de Sheets
        credentials_with_scope = get_credentials_with_scopes(credentials, SHEETS_SCOPES)
        
        gspread_client = gspread.authorize(credentials_with_scope)
        spreadsheet = gspread_client.open_by_key(spreadsheet_id)
        worksheet = spreadsheet.worksheet(worksheet_name)
        
        # Obtener todos los valores
        all_values = worksheet.get_all_values()
        
        if not all_values or len(all_values) < 2:
            print("[EMAIL] Warning: Sheet is empty or has no data rows")
            sys.stdout.flush()
            return None, {}
        
        # Primera fila son los headers
        headers = [str(h).strip() for h in all_values[0]]
        
        # Buscar índices de columnas
        search_col_idx = None
        email_col_idx = None
        additional_col_indices = {}
        
        for idx, header in enumerate(headers):
            header_lower = header.lower()
            if header_lower == search_column.lower():
                search_col_idx = idx
            if header_lower == email_column.lower():
                email_col_idx = idx
            if additional_columns:
                for add_col in additional_columns:
                    if header_lower == add_col.lower():
                        additional_col_indices[add_col] = idx
        
        if search_col_idx is None:
            print(f"[EMAIL] Error: Search column '{search_column}' not found. Available: {headers}")
            sys.stdout.flush()
            return None, {}
        
        if email_col_idx is None:
            print(f"[EMAIL] Error: Email column '{email_column}' not found. Available: {headers}")
            sys.stdout.flush()
            return None, {}
        
        # Buscar el valor en las filas
        search_value_normalized = str(search_value).strip().lower()
        
        for row in all_values[1:]:  # Saltar header
            if len(row) > search_col_idx:
                cell_value = str(row[search_col_idx]).strip().lower()
                if cell_value == search_value_normalized:
                    # Encontrado
                    email = row[email_col_idx].strip() if len(row) > email_col_idx else None
                    
                    # Obtener columnas adicionales
                    additional_data = {}
                    for col_name, col_idx in additional_col_indices.items():
                        if len(row) > col_idx:
                            additional_data[col_name] = row[col_idx].strip()
                    
                    print(f"[EMAIL] Found email: {email}")
                    if additional_data:
                        print(f"[EMAIL] Additional data: {additional_data}")
                    sys.stdout.flush()
                    
                    return email, additional_data
        
        print(f"[EMAIL] No match found for '{search_value}' in column '{search_column}'")
        sys.stdout.flush()
        return None, {}
        
    except Exception as e:
        print(f"[EMAIL] Error searching in Google Sheets: {str(e)}")
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return None, {}


def search_emails_by_multiple_criteria(
    credentials,
    spreadsheet_id: str,
    worksheet_name: str,
    search_criteria: Dict[str, str],
    email_column: str,
    match_all: bool = True
) -> List[Tuple[str, Dict[str, str]]]:
    """
    Busca correos que coincidan con múltiples criterios.
    
    Args:
        credentials: Credenciales de GCP
        spreadsheet_id: ID del Google Sheets
        worksheet_name: Nombre de la hoja de trabajo
        search_criteria: Diccionario con {columna: valor} para buscar
        email_column: Nombre de la columna que contiene el correo
        match_all: Si True, todas las condiciones deben cumplirse (AND). 
                   Si False, cualquier condición es suficiente (OR)
        
    Returns:
        Lista de tuplas: [(email, {row_data}), ...]
    """
    try:
        print(f"[EMAIL] Searching with multiple criteria in: {spreadsheet_id}/{worksheet_name}")
        print(f"[EMAIL] Criteria: {search_criteria} (match_all={match_all})")
        sys.stdout.flush()
        
        credentials_with_scope = get_credentials_with_scopes(credentials, SHEETS_SCOPES)
        
        gspread_client = gspread.authorize(credentials_with_scope)
        spreadsheet = gspread_client.open_by_key(spreadsheet_id)
        worksheet = spreadsheet.worksheet(worksheet_name)
        
        all_values = worksheet.get_all_values()
        
        if not all_values or len(all_values) < 2:
            print("[EMAIL] Warning: Sheet is empty or has no data rows")
            sys.stdout.flush()
            return []
        
        headers = [str(h).strip() for h in all_values[0]]
        
        # Mapear columnas de búsqueda
        search_col_map = {}  # {columna_nombre: índice}
        email_col_idx = None
        
        for idx, header in enumerate(headers):
            header_lower = header.lower()
            if header_lower == email_column.lower():
                email_col_idx = idx
            for col_name in search_criteria.keys():
                if header_lower == col_name.lower():
                    search_col_map[col_name] = idx
        
        if email_col_idx is None:
            print(f"[EMAIL] Error: Email column '{email_column}' not found")
            sys.stdout.flush()
            return []
        
        # Buscar coincidencias
        results = []
        
        for row in all_values[1:]:
            matches = []
            
            for col_name, search_value in search_criteria.items():
                col_idx = search_col_map.get(col_name)
                if col_idx is not None and len(row) > col_idx:
                    cell_value = str(row[col_idx]).strip().lower()
                    search_normalized = str(search_value).strip().lower()
                    matches.append(cell_value == search_normalized)
                else:
                    matches.append(False)
            
            # Evaluar según match_all
            if match_all:
                is_match = all(matches) if matches else False
            else:
                is_match = any(matches) if matches else False
            
            if is_match:
                email = row[email_col_idx].strip() if len(row) > email_col_idx else None
                if email:
                    row_data = {headers[i]: row[i] for i in range(len(row)) if i < len(headers)}
                    results.append((email, row_data))
        
        print(f"[EMAIL] Found {len(results)} matching rows")
        sys.stdout.flush()
        
        return results
        
    except Exception as e:
        print(f"[EMAIL] Error searching with multiple criteria: {str(e)}")
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return []


def create_message(
    sender: str,
    to: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, str]:
    """
    Crea un mensaje de correo en formato MIME.
    
    Args:
        sender: Correo del remitente
        to: Correo del destinatario (o lista separada por comas)
        subject: Asunto del correo
        body_text: Cuerpo del correo en texto plano
        body_html: Cuerpo del correo en HTML (opcional)
        cc: Lista de correos en copia (opcional)
        bcc: Lista de correos en copia oculta (opcional)
        attachments: Lista de adjuntos [{filename, content, mime_type}] (opcional)
        
    Returns:
        Dict con el mensaje codificado en base64 para Gmail API
    """
    if body_html or attachments:
        message = MIMEMultipart('alternative' if body_html and not attachments else 'mixed')
    else:
        message = MIMEText(body_text, 'plain', 'utf-8')
    
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    
    if cc:
        message['cc'] = ', '.join(cc)
    if bcc:
        message['bcc'] = ', '.join(bcc)
    
    # Agregar cuerpo
    if isinstance(message, MIMEMultipart):
        if body_html:
            # Crear parte alternativa con texto y HTML
            if attachments:
                alt_part = MIMEMultipart('alternative')
                alt_part.attach(MIMEText(body_text, 'plain', 'utf-8'))
                alt_part.attach(MIMEText(body_html, 'html', 'utf-8'))
                message.attach(alt_part)
            else:
                message.attach(MIMEText(body_text, 'plain', 'utf-8'))
                message.attach(MIMEText(body_html, 'html', 'utf-8'))
        else:
            message.attach(MIMEText(body_text, 'plain', 'utf-8'))
        
        # Agregar adjuntos
        if attachments:
            for attachment in attachments:
                filename = attachment.get('filename', 'attachment')
                content = attachment.get('content')  # bytes
                mime_type = attachment.get('mime_type', 'application/octet-stream')
                
                if content:
                    main_type, sub_type = mime_type.split('/', 1) if '/' in mime_type else ('application', 'octet-stream')
                    part = MIMEBase(main_type, sub_type)
                    part.set_payload(content if isinstance(content, bytes) else content.encode())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment', filename=filename)
                    message.attach(part)
    
    # Codificar en base64 URL-safe
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    
    return {'raw': raw_message}


def send_email(
    credentials,
    sender: str,
    to: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    user_id: str = 'me'
) -> Tuple[bool, Dict[str, Any]]:
    """
    Envía un correo usando Gmail API.
    
    Args:
        credentials: Credenciales OAuth2 para Gmail
        sender: Correo del remitente
        to: Correo del destinatario
        subject: Asunto del correo
        body_text: Cuerpo del correo en texto plano
        body_html: Cuerpo del correo en HTML (opcional)
        cc: Lista de correos en copia (opcional)
        bcc: Lista de correos en copia oculta (opcional)
        attachments: Lista de adjuntos (opcional)
        user_id: ID del usuario de Gmail (default: 'me')
        
    Returns:
        Tuple: (success, result_dict)
    """
    try:
        print(f"[EMAIL] Sending email to: {to}")
        print(f"[EMAIL] Subject: {subject}")
        if cc:
            print(f"[EMAIL] CC: {cc}")
        if bcc:
            print(f"[EMAIL] BCC: {bcc}")
        sys.stdout.flush()
        
        # Construir servicio de Gmail
        service = build('gmail', 'v1', credentials=credentials)
        
        # Crear mensaje
        message = create_message(
            sender=sender,
            to=to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            cc=cc,
            bcc=bcc,
            attachments=attachments
        )
        
        # Enviar mensaje
        sent_message = service.users().messages().send(
            userId=user_id,
            body=message
        ).execute()
        
        print(f"[EMAIL] Email sent successfully. Message ID: {sent_message.get('id')}")
        sys.stdout.flush()
        
        return True, {
            'message_id': sent_message.get('id'),
            'thread_id': sent_message.get('threadId'),
            'label_ids': sent_message.get('labelIds', [])
        }
        
    except HttpError as e:
        error_msg = f"Gmail API error: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        return False, {'error': error_msg, 'status_code': e.resp.status if hasattr(e, 'resp') else None}
        
    except Exception as e:
        error_msg = f"Error sending email: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return False, {'error': error_msg}


def send_email_with_sheet_lookup(
    credentials,
    spreadsheet_id: str,
    worksheet_name: str,
    search_column: str,
    search_value: str,
    email_column: str,
    sender: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    template_variables: Optional[Dict[str, str]] = None,
    sheets_credentials = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Busca el correo en Google Sheets y envía el email.
    Soporta variables de plantilla en subject, body_text y body_html.
    
    Args:
        credentials: Credenciales OAuth2 para Gmail
        spreadsheet_id: ID del Google Sheets
        worksheet_name: Nombre de la hoja de trabajo
        search_column: Columna donde buscar
        search_value: Valor a buscar
        email_column: Columna con el correo
        sender: Correo del remitente
        subject: Asunto del correo (puede contener {variables})
        body_text: Cuerpo en texto (puede contener {variables})
        body_html: Cuerpo en HTML opcional (puede contener {variables})
        cc: Lista de correos en copia
        bcc: Lista de correos en copia oculta
        attachments: Lista de adjuntos
        template_variables: Variables adicionales para reemplazar en plantillas
        sheets_credentials: Credenciales separadas para Sheets (opcional, usa credentials si no se proporciona)
        
    Returns:
        Tuple: (success, result_dict)
    """
    try:
        # Usar credenciales separadas para Sheets si se proporcionan
        sheets_creds = sheets_credentials or credentials
        
        # Buscar el correo en Google Sheets
        # Obtener todas las columnas de la fila para usarlas como variables
        all_columns = []
        
        # Primero obtener los headers para saber qué columnas adicionales pedir
        credentials_with_scope = get_credentials_with_scopes(sheets_creds, SHEETS_SCOPES)
        gspread_client = gspread.authorize(credentials_with_scope)
        spreadsheet = gspread_client.open_by_key(spreadsheet_id)
        worksheet = spreadsheet.worksheet(worksheet_name)
        headers = worksheet.row_values(1)
        all_columns = [h.strip() for h in headers if h.strip() and h.strip().lower() != email_column.lower() and h.strip().lower() != search_column.lower()]
        
        # Buscar email y datos adicionales
        email, row_data = search_email_in_sheet(
            credentials=sheets_creds,
            spreadsheet_id=spreadsheet_id,
            worksheet_name=worksheet_name,
            search_column=search_column,
            search_value=search_value,
            email_column=email_column,
            additional_columns=all_columns
        )
        
        if not email:
            return False, {
                'error': f"No email found for {search_column}='{search_value}'",
                'search_column': search_column,
                'search_value': search_value
            }
        
        # Preparar variables para plantillas
        variables = {
            search_column: search_value,
            email_column: email,
            **row_data
        }
        
        if template_variables:
            variables.update(template_variables)
        
        # Reemplazar variables en subject, body_text y body_html
        final_subject = subject
        final_body_text = body_text
        final_body_html = body_html
        
        for var_name, var_value in variables.items():
            placeholder = '{' + var_name + '}'
            if var_value:
                final_subject = final_subject.replace(placeholder, str(var_value))
                final_body_text = final_body_text.replace(placeholder, str(var_value))
                if final_body_html:
                    final_body_html = final_body_html.replace(placeholder, str(var_value))
        
        # Enviar el correo (con credenciales OAuth2 de Gmail)
        success, result = send_email(
            credentials=credentials,
            sender=sender,
            to=email,
            subject=final_subject,
            body_text=final_body_text,
            body_html=final_body_html,
            cc=cc,
            bcc=bcc,
            attachments=attachments
        )
        
        # Agregar información de búsqueda al resultado
        result['recipient_email'] = email
        result['search_data'] = {
            'column': search_column,
            'value': search_value
        }
        result['row_data'] = row_data
        
        return success, result
        
    except Exception as e:
        error_msg = f"Error in send_email_with_sheet_lookup: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        import traceback
        traceback.print_exc()
        return False, {'error': error_msg}


def send_bulk_emails(
    credentials,
    spreadsheet_id: str,
    worksheet_name: str,
    email_column: str,
    sender: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None,
    filter_criteria: Optional[Dict[str, str]] = None,
    sheets_credentials = None
) -> Dict[str, Any]:
    """
    Envía correos a múltiples destinatarios de un Google Sheet.
    
    Args:
        credentials: Credenciales OAuth2 para Gmail
        spreadsheet_id: ID del Google Sheets
        worksheet_name: Nombre de la hoja
        email_column: Columna con los correos
        sender: Correo del remitente
        subject: Asunto (puede contener {variables})
        body_text: Cuerpo (puede contener {variables})
        body_html: Cuerpo HTML opcional
        filter_criteria: Criterios para filtrar filas (opcional)
        sheets_credentials: Credenciales separadas para Sheets (opcional)
        
    Returns:
        Dict con resultados del envío masivo
    """
    results = {
        'total': 0,
        'sent': 0,
        'failed': 0,
        'details': []
    }
    
    try:
        # Usar credenciales separadas para Sheets si se proporcionan
        sheets_creds = sheets_credentials or credentials
        
        credentials_with_scope = get_credentials_with_scopes(sheets_creds, SHEETS_SCOPES)
        gspread_client = gspread.authorize(credentials_with_scope)
        spreadsheet = gspread_client.open_by_key(spreadsheet_id)
        worksheet = spreadsheet.worksheet(worksheet_name)
        
        all_values = worksheet.get_all_values()
        
        if not all_values or len(all_values) < 2:
            return {'error': 'Sheet is empty', **results}
        
        headers = [str(h).strip() for h in all_values[0]]
        email_col_idx = None
        
        for idx, header in enumerate(headers):
            if header.lower() == email_column.lower():
                email_col_idx = idx
                break
        
        if email_col_idx is None:
            return {'error': f"Email column '{email_column}' not found", **results}
        
        # Procesar cada fila
        for row_idx, row in enumerate(all_values[1:], start=2):
            # Crear diccionario de la fila
            row_data = {headers[i]: row[i] if i < len(row) else '' for i in range(len(headers))}
            
            # Aplicar filtros si existen
            if filter_criteria:
                match = True
                for col, value in filter_criteria.items():
                    if row_data.get(col, '').strip().lower() != value.strip().lower():
                        match = False
                        break
                if not match:
                    continue
            
            email = row[email_col_idx].strip() if email_col_idx < len(row) else ''
            
            if not email or '@' not in email:
                continue
            
            results['total'] += 1
            
            # Reemplazar variables
            final_subject = subject
            final_body_text = body_text
            final_body_html = body_html
            
            for var_name, var_value in row_data.items():
                placeholder = '{' + var_name + '}'
                final_subject = final_subject.replace(placeholder, str(var_value))
                final_body_text = final_body_text.replace(placeholder, str(var_value))
                if final_body_html:
                    final_body_html = final_body_html.replace(placeholder, str(var_value))
            
            # Enviar correo (con credenciales OAuth2 de Gmail)
            success, result = send_email(
                credentials=credentials,
                sender=sender,
                to=email,
                subject=final_subject,
                body_text=final_body_text,
                body_html=final_body_html
            )
            
            if success:
                results['sent'] += 1
                results['details'].append({
                    'row': row_idx,
                    'email': email,
                    'status': 'sent',
                    'message_id': result.get('message_id')
                })
            else:
                results['failed'] += 1
                results['details'].append({
                    'row': row_idx,
                    'email': email,
                    'status': 'failed',
                    'error': result.get('error')
                })
        
        return results
        
    except Exception as e:
        error_msg = f"Error in send_bulk_emails: {str(e)}"
        print(f"[EMAIL] {error_msg}")
        sys.stdout.flush()
        return {'error': error_msg, **results}


def check_gmail_auth_status(token_path: str = None) -> Dict[str, Any]:
    """
    Verifica el estado de la autorización de Gmail.
    
    Args:
        token_path: Ruta al archivo de token
        
    Returns:
        Dict con el estado de la autorización
    """
    token_path = token_path or TOKEN_PATH
    
    result = {
        'authorized': False,
        'token_exists': False,
        'token_valid': False,
        'email': None,
        'scopes': None,
        'error': None
    }
    
    if not os.path.exists(token_path):
        result['error'] = 'No token file found. Authorization required.'
        return result
    
    result['token_exists'] = True
    
    try:
        # Cargar sin especificar scopes para evitar validación estricta
        creds = Credentials.from_authorized_user_file(token_path)
        result['scopes'] = list(creds.scopes) if creds.scopes else []
        
        if creds.valid:
            result['token_valid'] = True
            result['authorized'] = True
            
            # Obtener email del usuario
            service = build('gmail', 'v1', credentials=creds)
            profile = service.users().getProfile(userId='me').execute()
            result['email'] = profile.get('emailAddress')
            
        elif creds.expired and creds.refresh_token:
            # Intentar refrescar
            creds.refresh(Request())
            save_token(creds, token_path)
            result['token_valid'] = True
            result['authorized'] = True
            
            service = build('gmail', 'v1', credentials=creds)
            profile = service.users().getProfile(userId='me').execute()
            result['email'] = profile.get('emailAddress')
        else:
            result['error'] = 'Token expired and no refresh token available.'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result
