# tests/unit/utils/test_s3_path_helper.py
# Pruebas para el helper de rutas S3

import pytest
from src.utils.s3_path_helper import encode_s3_key, decode_s3_key

def test_encode_s3_key():
    """Prueba la función de codificación para claves S3."""
    # Caso simple
    assert encode_s3_key("file.pdf") == "file.pdf"
    
    # Con espacios
    assert encode_s3_key("my file.pdf") == "my%20file.pdf"
    
    # Con caracteres especiales
    assert encode_s3_key("año_2023.pdf") == "a%C3%B1o_2023.pdf"
    
    # Con caracteres especiales y espacios
    assert encode_s3_key("contraseña año 2023.pdf") == "contrase%C3%B1a%20a%C3%B1o%202023.pdf"
    
    # Caso nulo
    assert encode_s3_key(None) is None
    
    # Caso vacío
    assert encode_s3_key("") == ""

def test_decode_s3_key():
    """Prueba la función de decodificación para claves S3."""
    # Caso simple
    assert decode_s3_key("file.pdf") == "file.pdf"
    
    # Con espacios codificados
    assert decode_s3_key("my%20file.pdf") == "my file.pdf"
    
    # Con caracteres especiales codificados
    assert decode_s3_key("a%C3%B1o_2023.pdf") == "año_2023.pdf"
    
    # Con caracteres especiales y espacios codificados
    assert decode_s3_key("contrase%C3%B1a%20a%C3%B1o%202023.pdf") == "contraseña año 2023.pdf"
    
    # Caso nulo
    assert decode_s3_key(None) is None
    
    # Caso vacío
    assert decode_s3_key("") == ""

def test_round_trip_encoding():
    """Prueba que la codificación y posterior decodificación devuelve el valor original."""
    original = "Mi archivo con espacios y caracteres: áéíóú ñ €.pdf"
    encoded = encode_s3_key(original)
    decoded = decode_s3_key(encoded)
    
    assert decoded == original