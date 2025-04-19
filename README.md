# DocPilot Backend

Sistema backend para gestión de documentos con procesamiento inteligente basado en AWS Serverless.

## Descripción general

DocPilot es una plataforma multi-tenant para la gestión, procesamiento y análisis de documentos. Utiliza servicios serverless de AWS para proporcionar una solución escalable, segura y rentable.

Características principales:
- Procesamiento de documentos con IA (usando Amazon Bedrock)
- Modelo multi-tenant con gestión de planes y límites
- Detección de documentos duplicados
- Sistema de alertas configurable
- Control de acceso granular basado en roles
- Recepción y procesamiento de documentos por email
- Estadísticas avanzadas e informes

## Estructura del proyecto

```
docpilot-backend/
├── serverless.yml        # Definición de infraestructura serverless
├── package.json          # Dependencias y scripts para node/serverless
├── requirements.txt      # Dependencias de Python para las funciones Lambda
├── src/
│   ├── handlers/         # Funciones Lambda principales
│   │   ├── alerts/       # Sistema de alertas
│   │   ├── email/        # Configuración y manejo de correos
│   │   ├── stats/        # Estadísticas y análisis
│   │   └── ...           # Otras funciones Lambda
│   └── utils/            # Utilidades compartidas
└── tests/                # Pruebas unitarias y de integración
```

## Requisitos

- Node.js 14+ y npm
- Python 3.9+
- AWS CLI configurado con credenciales apropiadas
- Serverless Framework v3+
- Docker (para empaquetado de dependencias)

## Instalación y configuración

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/tu-organizacion/docpilot-backend.git
   cd docpilot-backend
   ```

2. Instalar dependencias de Node.js:
   ```bash
   npm install
   ```

3. Instalar dependencias de Python:
   ```bash
   pip install -r requirements.txt
   ```

4. Configurar variables de entorno (opcional):
   Crea un archivo `.env` en la raíz del proyecto con las variables necesarias.

## Despliegue

Para desplegar en el entorno de desarrollo:

```bash
serverless deploy
```

Para desplegar en un entorno específico:

```bash
serverless deploy --stage production
```

## Componentes principales

### Gestión de documentos
- `documentProcessor`: Procesa documentos con IA
- `documentManager`: API para gestión de documentos
- `generateUrl`: Genera URLs para subida de archivos
- `confirmUpload`: Confirma subidas exitosas

### Gestión de tenants
- `tenantManagement`: API para gestión de tenants
- `tenantOnboarding`: Proceso de onboarding de nuevos tenants

### Gestión de usuarios
- `userManagement`: API para gestión de usuarios

### Sistema de alertas
- `alertRuleManager`: Gestión de reglas de alertas
- `alertProcessor`: Procesamiento de alertas
- `alertNotifier`: Envío de notificaciones
- `scheduledAlertChecker`: Verificación de condiciones temporales

### Estadísticas y análisis
- `metricsCollector`: Recolección de métricas
- `statisticsApi`: API para consulta de estadísticas
- `reportGenerator`: Generación de informes

### Sistema de email
- `emailHandler`: Procesamiento de emails recibidos
- `sesConfigurator`: Configuración de dominios en SES

### Control de acceso
- `roleManagement`: Gestión de roles y permisos

## Recursos AWS

El sistema utiliza los siguientes recursos en AWS:

- **Lambda**: Funciones serverless
- **DynamoDB**: Almacenamiento de datos
- **S3**: Almacenamiento de documentos
- **Cognito**: Autenticación de usuarios
- **API Gateway**: Exposición de APIs REST
- **EventBridge**: Programación de tareas
- **SES**: Envío y recepción de correos
- **Bedrock**: Procesamiento con IA
- **CloudWatch**: Logs y monitoreo

## Desarrollo y pruebas

### Ejecución local

Para ejecutar funciones localmente:

```bash
serverless invoke local -f functionName -p event.json
```

Para simular eventos de API Gateway:

```bash
serverless offline
```

### Pruebas

Ejecutar pruebas unitarias:

```bash
pytest tests/unit/
```

Ejecutar pruebas de integración:

```bash
pytest tests/integration/
```

## Consideraciones de seguridad

- Las funciones Lambda utilizan permisos de IAM mínimos
- La información sensible se almacena en AWS Secrets Manager
- Se implementa validación de entrada en todas las APIs
- El sistema de control de acceso garantiza acceso sólo a datos autorizados
- Todos los documentos se almacenan en buckets S3 privados

## Monitoreo

El sistema incluye configuración para monitoreo a través de CloudWatch:

- Logs detallados de todas las funciones
- Alertas para errores y latencia alta
- Métricas personalizadas para uso de recursos
- Dashboard para visualización de estado del sistema

## Contribución

1. Crea un fork del repositorio
2. Crea una rama para tu función (`git checkout -b feature/nueva-funcion`)
3. Realiza tus cambios y añade pruebas
4. Ejecuta las pruebas para asegurar que pasan
5. Haz commit de tus cambios (`git commit -am 'Añade nueva función'`)
6. Haz push a la rama (`git push origin feature/nueva-funcion`)
7. Crea un Pull Request

## Licencia

Este proyecto está licenciado bajo [tu licencia aquí]

## Contacto

Para consultas sobre el proyecto, contactar a Ereace.es