# docpilot-backend/tests/utils/test_s3_path_helper.py
"""
Pruebas unitarias para el módulo de utilidades s3_path_helper.py
Ejecutar con: python -m pytest tests/utils/test_s3_path_helper.py -v
"""

import sys
import os
import pytest

# Añadir directorio raíz del proyecto al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.s3_path_helper import (
    encode_s3_key,
    decode_s3_key,
    is_encoded,
    ensure_encoded_key,
    extract_filename_from_key,
    split_s3_path
)

class TestS3PathHelper:
    """Pruebas para s3_path_helper.py"""
    
    def test_encode_decode_simple(self):
        """Prueba básica de codificación y decodificación"""
        original = "simple.pdf"
        encoded = encode_s3_key(original)
        decoded = decode_s3_key(encoded)
        assert original == decoded
        assert encoded == original  # No debería cambiar para nombres simples
    
    def test_encode_decode_special_chars(self):
        """Prueba con caracteres especiales"""
        special_cases = [
            "documento con espacios.pdf",
            "archivo_con_ñ.pdf",
            "contráto.pdf",
            "reporte-año-2023.docx",
            "documento@empresa.docx",
            "archivo_100%.txt"
        ]
        
        for original in special_cases:
            encoded = encode_s3_key(original)
            decoded = decode_s3_key(encoded)
            assert original == decoded
            assert is_encoded(encoded) or encoded == original
    
    def test_encode_already_encoded(self):
        """Prueba que no recodifica si ya está codificado"""
        already_encoded = "documento%20con%20espacios.pdf"
        encoded_again = encode_s3_key(already_encoded)
        assert encoded_again == already_encoded
    
    def test_is_encoded(self):
        """Prueba la detección de cadenas ya codificadas"""
        encoded_strings = [
            "documento%20con%20espacios.pdf",
            "contrato%C3%B1a.pdf",
            "a%C3%B1o-2023.docx"
        ]
        
        for s in encoded_strings:
            assert is_encoded(s)
        
        not_encoded_strings = [
            "simple.pdf",
            "contrato.pdf",
            "with spaces.pdf",
            "año-2023.docx"
        ]
        
        for s in not_encoded_strings:
            assert not is_encoded(s)
    
    def test_ensure_encoded_key(self):
        """Prueba la función para asegurar que una clave esté codificada"""
        # No debería cambiar si ya está codificada
        already_encoded = "documento%20con%20espacios.pdf"
        assert ensure_encoded_key(already_encoded) == already_encoded
        
        # Debería codificar si no lo está
        original = "documento con espacios.pdf"
        encoded = ensure_encoded_key(original)
        assert encoded != original
        assert is_encoded(encoded)
    
    def test_extract_filename(self):
        """Prueba la extracción del nombre de archivo de una ruta"""
        test_cases = [
            ("tenants/tenant1/raw/manual/123/file.pdf", "file.pdf"),
            ("tenants/tenant1/raw/email/456/file%20with%20spaces.pdf", "file with spaces.pdf"),
            ("raw/manual/789/año-2023.docx", "año-2023.docx"),
            ("raw/email/101/report%C3%B1.docx", "reportñ.docx")
        ]
        
        for path, expected in test_cases:
            assert extract_filename_from_key(path) == expected
    
    def test_split_s3_path(self):
        """Prueba la división de rutas S3 en componentes"""
        # Formato multitenant
        path1 = "tenants/tenant1/raw/manual/123/file.pdf"
        info1 = split_s3_path(path1)
        assert info1['tenant_id'] == "tenant1"
        assert info1['type'] == "raw"
        assert info1['source'] == "manual"
        assert info1['doc_id'] == "123"
        assert info1['filename'] == "file.pdf"
        
        # Formato multitenant con nombre codificado
        path2 = "tenants/tenant2/raw/email/456/file%20with%20spaces.pdf"
        info2 = split_s3_path(path2)
        assert info2['tenant_id'] == "tenant2"
        assert info2['type'] == "raw"
        assert info2['source'] == "email"
        assert info2['doc_id'] == "456"
        assert info2['filename'] == "file with spaces.pdf"
        
        # Formato legacy
        path3 = "raw/manual/789/document.pdf"
        info3 = split_s3_path(path3)
        assert info3['tenant_id'] == "default"
        assert info3['type'] == "raw"
        assert info3['source'] == "manual"
        assert info3['doc_id'] == "789"
        assert info3['filename'] == "document.pdf"
        
        # Formato no estándar
        path4 = "other/path/to/file.pdf"
        info4 = split_s3_path(path4)
        assert info4['tenant_id'] is None
        assert info4['type'] is None
        assert info4['filename'] == "file.pdf"

    def test_path_with_unicode_chars(self):
        """Prueba con caracteres Unicode más complejos"""
        unicode_cases = [
            "documento-áéíóúÁÉÍÓÚ.pdf",
            "文件.docx",  # Caracteres chinos
            "документ.pdf",  # Caracteres cirílicos
            "∞≈≠≤≥±×÷.txt"  # Símbolos matemáticos
        ]
        
        for original in unicode_cases:
            encoded = encode_s3_key(original)
            decoded = decode_s3_key(encoded)
            assert decoded == original
            assert is_encoded(encoded) or encoded == original