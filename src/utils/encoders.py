import json
import decimal
from datetime import datetime

class DecimalEncoder(json.JSONEncoder):
    """
    Codificador JSON personalizado para manejar objetos Decimal de DynamoDB y datetime.
    """
    def default(self, o): # PEP8 prefiere 'o' a 'obj' para variables de un solo caracter
        if isinstance(o, decimal.Decimal):
            # Convertir Decimal a float. Considerar string si se necesita precisión exacta exacta
            # y el consumidor puede manejar strings numéricos.
            return float(o) 
        if isinstance(o, datetime):
            return o.isoformat()
        # Dejar que la clase base maneje otros tipos o lance error
        return super(DecimalEncoder, self).default(o) 