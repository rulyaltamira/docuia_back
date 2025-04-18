# docpilot-backend/src/utils/s3_path_helper.py
# Utilidades para manejar caracteres especiales en rutas de S3

import urllib.parse
import re
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def encode_s3_key(raw_key):
    """
    Codifica una clave S3 para manejar correctamente caracteres especiales.
    
    Args:
        raw_key (str): La clave original que puede contener caracteres especiales
        
    Returns:
        str: La clave codificada segura para S3
    """
    if not raw_key:
        return raw_key
        
    # Si ya está codificada, la retornamos como está
    if is_encoded(raw_key):
        return raw_key
    
    # Dividir la ruta para codificar sólo los componentes individuales (nombre de archivo)
    parts = raw_key.split('/')
    encoded_parts = []
    
    for part in parts:
        if part:  # No codificar partes vacías (cuando hay // consecutivos)
            # Codificar caracteres especiales manteniendo la estructura básica
            encoded = urllib.parse.quote(part, safe='-_.~')
            encoded_parts.append(encoded)
        else:
            encoded_parts.append('')
    
    # Reconstruir la ruta
    encoded_key = '/'.join(encoded_parts)
    
    logger.debug(f"Codificada clave S3: '{raw_key}' -> '{encoded_key}'")
    return encoded_key

def decode_s3_key(encoded_key):
    """
    Decodifica una clave S3 para mostrar los caracteres especiales correctamente.
    
    Args:
        encoded_key (str): La clave codificada de S3
        
    Returns:
        str: La clave decodificada para visualización
    """
    if not encoded_key:
        return encoded_key
        
    # Dividir la ruta para decodificar sólo los componentes individuales
    parts = encoded_key.split('/')
    decoded_parts = []
    
    for part in parts:
        if part:  # No decodificar partes vacías
            try:
                # Decodificar los caracteres especiales
                decoded = urllib.parse.unquote(part)
                decoded_parts.append(decoded)
            except Exception as e:
                logger.warning(f"Error decodificando parte '{part}': {str(e)}")
                decoded_parts.append(part)  # Mantener la parte original en caso de error
        else:
            decoded_parts.append('')
    
    # Reconstruir la ruta
    decoded_key = '/'.join(decoded_parts)
    
    logger.debug(f"Decodificada clave S3: '{encoded_key}' -> '{decoded_key}'")
    return decoded_key

def ensure_encoded_key(key):
    """
    Asegura que una clave esté correctamente codificada para S3.
    Si ya está codificada, la retorna como está.
    
    Args:
        key (str): La clave que puede o no estar codificada
        
    Returns:
        str: La clave codificada segura para S3
    """
    if not key:
        return key
        
    if is_encoded(key):
        return key
    else:
        return encode_s3_key(key)

def is_encoded(key):
    """
    Verifica si una clave ya está codificada para S3.
    
    Args:
        key (str): La clave a verificar
        
    Returns:
        bool: True si la clave ya está codificada, False en caso contrario
    """
    if not key:
        return False
        
    # Heurística para determinar si una clave ya está codificada
    # Buscamos patrones como %20, %C3%B1, etc. comunes en URL encoding
    encoding_pattern = r'%[0-9A-Fa-f]{2}'
    
    # Si encontramos patrones de codificación y no hay caracteres no ASCII, probablemente está codificada
    has_encoding_pattern = bool(re.search(encoding_pattern, key))
    has_special_chars = any(ord(c) > 127 for c in key)
    
    # Si tiene patrones de codificación y no tiene caracteres especiales sin codificar
    return has_encoding_pattern and not has_special_chars

def extract_filename_from_key(key):
    """
    Extrae el nombre de archivo de una clave S3, decodificándolo si es necesario.
    
    Args:
        key (str): La clave S3 completa
        
    Returns:
        str: El nombre de archivo decodificado
    """
    if not key:
        return ""
        
    # Obtener la última parte de la ruta
    filename = key.split('/')[-1]
    
    # Decodificar si es necesario
    if is_encoded(filename):
        return decode_s3_key(filename)
    else:
        return filename

def split_s3_path(s3_path):
    """
    Divide una ruta S3 completa en partes (tenant, tipo, id, etc.)
    
    Args:
        s3_path (str): La ruta S3 completa
        
    Returns:
        dict: Diccionario con las partes divididas
    """
    parts = s3_path.strip('/').split('/')
    result = {
        'original_path': s3_path
    }
    
    # Estructura: "tenants/{tenant_id}/raw/{source}/{doc_id}/{filename}"
    # o legacy: "raw/{source}/{doc_id}/{filename}"
    if len(parts) >= 6 and parts[0] == 'tenants':
        result['tenant_id'] = parts[1]
        result['type'] = parts[2]  # 'raw' o 'processed'
        result['source'] = parts[3]  # 'email' o 'manual'
        result['doc_id'] = parts[4]
        result['filename'] = decode_s3_key(parts[5])
    elif len(parts) >= 4 and parts[0] == 'raw':
        result['tenant_id'] = 'default'
        result['type'] = parts[0]  # 'raw'
        result['source'] = parts[1]  # 'email' o 'manual'
        result['doc_id'] = parts[2]
        result['filename'] = decode_s3_key(parts[3])
    else:
        # Si no sigue la estructura esperada, devolver lo básico
        result['tenant_id'] = None
        result['type'] = None
        result['filename'] = decode_s3_key(parts[-1]) if parts else ""
    
    return result