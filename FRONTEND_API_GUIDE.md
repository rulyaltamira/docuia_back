# Guía de API para Desarrolladores Frontend

Este documento proporciona una visión general de cómo interactuar con el backend de DocPilot.

## 1. Información General

### 1.1. URL Base de la API

La URL base para todas las llamadas a la API se puede obtener de los `Outputs` del despliegue de Serverless (parámetro `ApiUrl`). Generalmente sigue el formato:
`https://{api_id}.execute-api.{region}.amazonaws.com/{stage}`

Por ejemplo: `https://abcdef123.execute-api.eu-west-1.amazonaws.com/dev`

### 1.2. Autenticación

La mayoría de los endpoints de esta API están protegidos y requieren autenticación mediante Amazon Cognito.
Cuando un usuario inicia sesión a través de Cognito, la aplicación frontend recibirá un **Token JWT (JSON Web Token)**. Este token debe incluirse en el encabezado `Authorization` de cada solicitud a un endpoint protegido.

**Ejemplo de encabezado:**
`Authorization: Bearer <jwt_token>`

Algunos endpoints, como los de onboarding inicial o verificación de email, pueden ser públicos y no requerir este encabezado. Esto se indicará en la descripción de cada endpoint.

### 1.3. CORS (Cross-Origin Resource Sharing)

CORS está habilitado para la mayoría de los endpoints, permitiendo que las aplicaciones frontend alojadas en diferentes dominios realicen solicitudes a la API. La configuración específica de CORS (orígenes permitidos, cabeceras, etc.) se define en `serverless.yml` para cada endpoint HTTP.

### 1.4. Formato de Solicitudes y Respuestas

Todas las solicitudes que envían datos (POST, PUT) deben usar `Content-Type: application/json` y enviar los datos en formato JSON en el cuerpo de la solicitud.
Las respuestas de la API también serán generalmente en formato JSON.

### 1.5. Manejo de Errores

Las respuestas de error de la API (ej. códigos 4xx, 5xx) típicamente incluirán un cuerpo JSON con un mensaje descriptivo del error, por ejemplo:
`{ "error": "Mensaje descriptivo del error" }` o `{ "message": "Mensaje descriptivo del error" }`

## 2. Endpoints de la API

A continuación, se describen los principales grupos de endpoints:

---

### 2.1. Carga de Documentos

#### 2.1.1. Generar URL Prefirmada para Subida
*   **Función:** `generateUrl`
*   **Descripción:** Genera URLs prefirmadas para subida de documentos directamente a S3.
*   **Endpoint:** `GET /generate-url`
*   **Autenticación:** Requerida (Cognito).
*   **Query Params Sugeridos:**
    *   `filename`: Nombre del archivo a subir.
    *   `contentType`: Tipo de contenido del archivo (ej. `application/pdf`).
    *   `tenant_id`: (Opcional, si se pasa como query param o en cabecera `x-tenant-id`).
    *   `user_id`: (Opcional, si se pasa como query param o en cabecera `x-user-id`).
*   **Respuesta Esperada (Éxito 200 OK):**
    ```json
    {
      "uploadUrl": "url_prefirmada_s3",
      "key": "ruta_del_archivo_en_s3"
    }
    ```

#### 2.1.2. Confirmar Subida de Documento
*   **Función:** `confirmUpload`
*   **Descripción:** Confirma la subida de un documento después de que se haya cargado a S3.
*   **Endpoint:** `POST /confirm-upload`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "key": "ruta_del_archivo_en_s3", // La obtenida de generate-url
      "filename": "nombre_original_del_archivo.pdf",
      "file_size": 102400, // Tamaño en bytes
      "content_type": "application/pdf",
      "tenant_id": "id_del_tenant",
      "user_id": "id_del_usuario_que_sube"
      // Otros metadatos relevantes
    }
    ```
*   **Respuesta Esperada (Éxito 200 OK):**
    ```json
    {
      "message": "Upload confirmed",
      "document_id": "id_del_documento_creado"
    }
    ```

---

### 2.2. Gestión de Tenants (Clientes)

#### 2.2.1. Listar Tenants
*   **Función:** `tenantManagement`
*   **Descripción:** Obtiene una lista de todos los tenants.
*   **Endpoint:** `GET /tenants`
*   **Autenticación:** Requerida (Cognito).

#### 2.2.2. Crear Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Crea un nuevo tenant.
*   **Endpoint:** `POST /tenants`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "name": "Nombre del Tenant",
      "email_admin": "admin@tenant.com",
      "plan_id": "plan_basico"
      // Otros campos relevantes para un tenant
    }
    ```

#### 2.2.3. Obtener Detalles de un Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Obtiene los detalles de un tenant específico.
*   **Endpoint:** `GET /tenants/{tenant_id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `tenant_id`: ID del tenant.

#### 2.2.4. Actualizar Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Actualiza la información de un tenant existente.
*   **Endpoint:** `PUT /tenants/{tenant_id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `tenant_id`: ID del tenant.
*   **Cuerpo de Solicititud:** Campos a actualizar del tenant.

#### 2.2.5. Eliminar Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Elimina un tenant.
*   **Endpoint:** `DELETE /tenants/{tenant_id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `tenant_id`: ID del tenant.

#### 2.2.6. Listar Planes de Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Obtiene los planes disponibles para tenants.
*   **Endpoint:** `GET /tenant-plans`
*   **Autenticación:** Requerida (Cognito).

#### 2.2.7. Obtener Uso de un Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Obtiene las estadísticas de uso para un tenant específico.
*   **Endpoint:** `GET /tenants/{tenant_id}/usage`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `tenant_id`: ID del tenant.

#### 2.2.8. Actualizar Plan de un Tenant
*   **Función:** `tenantManagement`
*   **Descripción:** Actualiza el plan de un tenant específico.
*   **Endpoint:** `PUT /tenants/{tenant_id}/plan`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `tenant_id`: ID del tenant.
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "new_plan_id": "nuevo_plan_premium"
    }
    ```

---

### 2.3. Onboarding de Tenants

#### 2.3.1. Iniciar Proceso de Onboarding (Público)
*   **Función:** `tenantOnboarding`
*   **Descripción:** Inicia el proceso de onboarding para un nuevo tenant (ej. auto-registro).
*   **Endpoint:** `POST /tenants/onboard`
*   **Autenticación:** No Requerida.
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "company_name": "Mi Nueva Empresa",
      "admin_email": "admin@nuevaempresa.com",
      "admin_name": "Nombre Admin",
      "password": "super_secret_password"
      // Otros campos necesarios para el onboarding
    }
    ```

#### 2.3.2. Iniciar Onboarding de Administrador (Público)
*   **Función:** `tenantOnboarding`
*   **Descripción:** Similar al anterior, podría ser una variante para administradores.
*   **Endpoint:** `POST /tenants/onboard/admin`
*   **Autenticación:** No Requerida.
*   **Cuerpo de Solicitud:** Similar a `/tenants/onboard`.

#### 2.3.3. Consultar Estado del Onboarding (Público)
*   **Función:** `tenantOnboarding`
*   **Descripción:** Consulta el estado de un proceso de onboarding en curso.
*   **Endpoint:** `GET /tenants/onboard/status`
*   **Autenticación:** No Requerida.
*   **Query Params Sugeridos:**
    *   `onboarding_id` o `email`: Identificador del proceso de onboarding.

#### 2.3.4. Verificar Email (Público)
*   **Función:** `verifyEmail`
*   **Descripción:** Endpoint al que se redirige al usuario para verificar su email (generalmente a través de un enlace en un correo).
*   **Endpoint:** `GET /tenants/verify-email`
*   **Autenticación:** No Requerida.
*   **Query Params Esperados:**
    *   `token`: Token de verificación.
    *   `user_id` o `email`: Identificador del usuario.
*   **Nota:** Este endpoint usualmente redirige al frontend a una página de éxito/error.

---

### 2.4. Gestión de Usuarios

#### 2.4.1. Listar Usuarios (de un tenant)
*   **Función:** `userManagement`
*   **Descripción:** Obtiene una lista de usuarios, usualmente filtrados por tenant_id (obtenido del token o como parámetro).
*   **Endpoint:** `GET /users`
*   **Autenticación:** Requerida (Cognito).
*   **Query Params Sugeridos:**
    *   `tenant_id`: (Si no se infiere automáticamente del contexto del usuario autenticado).

#### 2.4.2. Crear Usuario
*   **Función:** `userManagement`
*   **Descripción:** Crea un nuevo usuario dentro de un tenant.
*   **Endpoint:** `POST /users`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "email": "nuevo.usuario@tenant.com",
      "name": "Nombre del Usuario",
      "role_id": "id_del_rol", // o "role_name": "nombre_rol"
      "tenant_id": "id_del_tenant" // Si es necesario
      // Otros atributos del usuario
    }
    ```

#### 2.4.3. Obtener Detalles de un Usuario
*   **Función:** `userManagement`
*   **Descripción:** Obtiene los detalles de un usuario específico.
*   **Endpoint:** `GET /users/{user_id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `user_id`: ID del usuario.

#### 2.4.4. Actualizar Usuario
*   **Función:** `userManagement`
*   **Descripción:** Actualiza la información de un usuario existente.
*   **Endpoint:** `PUT /users/{user_id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `user_id`: ID del usuario.
*   **Cuerpo de Solicitud:** Campos a actualizar del usuario.

#### 2.4.5. Eliminar Usuario
*   **Función:** `userManagement`
*   **Descripción:** Elimina un usuario.
*   **Endpoint:** `DELETE /users/{user_id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `user_id`: ID del usuario.

---

### 2.5. Gestión de Documentos

#### 2.5.1. Listar Documentos
*   **Función:** `documentManager`
*   **Descripción:** Obtiene una lista de documentos (pertenecientes al tenant del usuario autenticado).
*   **Endpoint:** `GET /documents`
*   **Autenticación:** Requerida (Cognito).
*   **Query Params Sugeridos:**
    *   `tenant_id`: (Si no se infiere automáticamente).
    *   `searchTerm`, `dateFrom`, `dateTo`, `status`, `page`, `limit`: Para filtros y paginación.

#### 2.5.2. Obtener Detalles de un Documento
*   **Función:** `documentManager`
*   **Descripción:** Obtiene los detalles de un documento específico.
*   **Endpoint:** `GET /documents/{id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `id`: ID del documento.

#### 2.5.3. Eliminar Documento
*   **Función:** `documentManager`
*   **Descripción:** Elimina un documento.
*   **Endpoint:** `DELETE /documents/{id}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `id`: ID del documento.

#### 2.5.4. Ver Documento (Obtener URL de visualización)
*   **Función:** `documentManager`
*   **Descripción:** Obtiene una URL (posiblemente prefirmada) para ver el contenido del documento.
*   **Endpoint:** `GET /documents/{id}/view`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `id`: ID del documento.

#### 2.5.5. Obtener Resumen de Documento
*   **Función:** `documentManager`
*   **Descripción:** Obtiene un resumen generado por IA del documento.
*   **Endpoint:** `GET /documents/{id}/summary`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `id`: ID del documento.

#### 2.5.6. Verificar Duplicados de Documentos
*   **Función:** `checkDuplicates`
*   **Descripción:** Verifica si un documento (potencialmente a subir) es un duplicado.
*   **Endpoint:** `POST /documents/check-duplicate`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "file_hash": "hash_del_contenido_del_archivo", // SHA256 o similar
      "file_name": "nombre_del_archivo.pdf",
      "tenant_id": "id_del_tenant"
      // Otros metadatos para la comparación
    }
    ```

#### 2.5.7. Gestionar Documento Duplicado
*   **Función:** `handleDuplicate`
*   **Descripción:** Define la acción a tomar si se confirma un documento duplicado (ej. sobreescribir, versionar, rechazar).
*   **Endpoint:** `POST /documents/handle-duplicate`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "document_id_original": "id_del_doc_existente",
      "new_document_key_s3": "ruta_s3_del_nuevo_doc_duplicado",
      "action": "version" // "overwrite", "reject"
    }
    ```

---

### 2.6. Auditoría

#### 2.6.1. Registrar Evento de Auditoría
*   **Función:** `auditLogger`
*   **Descripción:** Permite registrar eventos de auditoría personalizados desde el frontend si es necesario.
*   **Endpoint:** `POST /audit/log`
*   **Autenticación:** Requerida (Cognito). (El `serverless.yml` lo muestra público, pero usualmente esto sería protegido o llamado internamente. Verificar si la intención es que sea público).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "user_id": "id_del_usuario",
      "tenant_id": "id_del_tenant",
      "action": "USER_LOGGED_IN",
      "details": { "ip_address": "1.2.3.4" }
    }
    ```

#### 2.6.2. Exportar Logs de Auditoría
*   **Función:** `auditLogger`
*   **Descripción:** Inicia un proceso para exportar logs de auditoría.
*   **Endpoint:** `POST /audit/export`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "date_from": "YYYY-MM-DD",
      "date_to": "YYYY-MM-DD",
      "format": "csv" // o "json"
    }
    ```

#### 2.6.3. Listar Logs de Auditoría
*   **Función:** `auditLogger`
*   **Descripción:** Obtiene una lista de logs de auditoría.
*   **Endpoint:** `GET /audit/logs`
*   **Autenticación:** Requerida (Cognito).
*   **Query Params Sugeridos:**
    *   `tenant_id`, `user_id`, `action_type`, `date_from`, `date_to`, `page`, `limit`.

---

### 2.7. Configuración de Email (SES)

#### 2.7.1. Configurar Dominio de Email
*   **Función:** `sesConfigurator`
*   **Descripción:** Inicia la configuración de un dominio de email para un tenant en SES.
*   **Endpoint:** `POST /email/domain`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "tenant_id": "id_del_tenant",
      "domain_name": "ejemplo.com"
    }
    ```

#### 2.7.2. Consultar Estado de Dominio de Email
*   **Función:** `sesConfigurator`
*   **Descripción:** Consulta el estado de verificación de un dominio de email.
*   **Endpoint:** `GET /email/domain/status`
*   **Autenticación:** Requerida (Cognito).
*   **Query Params Sugeridos:**
    *   `tenant_id`: ID del tenant.
    *   `domain_name`: Nombre del dominio.

#### 2.7.3. Configurar Regla de Recepción de Email
*   **Función:** `sesConfigurator`
*   **Descripción:** Crea reglas de recepción en SES para los emails del tenant.
*   **Endpoint:** `POST /email/receipt-rule`
*   **Autenticación:** Requerida (Cognito).
*   **Cuerpo de Solicitud Sugerido:**
    ```json
    {
      "tenant_id": "id_del_tenant",
      "domain_name": "ejemplo.com",
      "s3_bucket_name": "nombre-bucket-ses-tenant" // o configuración para invocar lambda
    }
    ```

#### 2.7.4. Listar Dominios de Email Configurados
*   **Función:** `sesConfigurator`
*   **Descripción:** Obtiene una lista de dominios configurados para un tenant.
*   **Endpoint:** `GET /email/domains`
*   **Autenticación:** Requerida (Cognito).
*   **Query Params Sugeridos:**
    *   `tenant_id`: ID del tenant.

#### 2.7.5. Eliminar Configuración de Dominio de Email
*   **Función:** `sesConfigurator`
*   **Descripción:** Elimina la configuración de un dominio de email para un tenant.
*   **Endpoint:** `DELETE /email/domain/{tenant_id}/{domain}`
*   **Autenticación:** Requerida (Cognito).
*   **Parámetros de Ruta:**
    *   `tenant_id`: ID del tenant.
    *   `domain`: Nombre del dominio.

---

### 2.8. Gestión de Alertas

#### 2.8.1. Gestión de Reglas de Alerta (`alertRuleManager`)

*   **Crear Regla de Alerta:**
    *   **Endpoint:** `POST /alerts/rules`
    *   **Autenticación:** Requerida.
    *   **Cuerpo de Solicitud:** Definición de la regla (ej. `{ "name": "Alerta Vencimiento Contrato", "tenant_id": "id_tenant", "conditions": { ... }, "severity": "critical" }`).
*   **Listar Reglas de Alerta:**
    *   **Endpoint:** `GET /alerts/rules`
    *   **Autenticación:** Requerida.
    *   **Query Params Sugeridos:** `tenant_id`.
*   **Obtener Regla de Alerta:**
    *   **Endpoint:** `GET /alerts/rules/{rule_id}`
    *   **Autenticación:** Requerida.
*   **Actualizar Regla de Alerta:**
    *   **Endpoint:** `PUT /alerts/rules/{rule_id}`
    *   **Autenticación:** Requerida.
    *   **Cuerpo de Solicitud:** Campos de la regla a actualizar.
*   **Eliminar Regla de Alerta:**
    *   **Endpoint:** `DELETE /alerts/rules/{rule_id}`
    *   **Autenticación:** Requerida.
*   **Validar Regla de Alerta:**
    *   **Endpoint:** `POST /alerts/rules/validate`
    *   **Autenticación:** Requerida.
    *   **Cuerpo de Solicitud:** Definición de la regla a validar.

#### 2.8.2. Notificación y Gestión de Alertas (`alertNotifier`)

*   **Notificar Alerta (Interno o Test):**
    *   **Endpoint:** `POST /alerts/notify`
    *   **Autenticación:** Requerida.
    *   **Cuerpo de Solicitud:** Detalles de la alerta a notificar.
*   **Crear/Actualizar Preferencias de Notificación:**
    *   **Endpoint:** `POST /alerts/preferences`
    *   **Autenticación:** Requerida.
    *   **Cuerpo de Solicitud:** `{ "user_id": "...", "tenant_id": "...", "notification_channels": { "email": true, "sms": false }, "alert_types": { "critical": true } }`.
*   **Obtener Preferencias de Notificación:**
    *   **Endpoint:** `GET /alerts/preferences`
    *   **Autenticación:** Requerida.
    *   **Query Params Sugeridos:** `user_id`, `tenant_id`.
*   **Procesar Alerta (Interno):**
    *   **Endpoint:** `POST /alerts/process` (Generalmente invocado internamente).
    *   **Autenticación:** Requerida.
*   **Obtener Detalles de Alerta:**
    *   **Endpoint:** `GET /alerts/{alert_id}`
    *   **Autenticación:** Requerida.
*   **Actualizar Estado de Alerta:**
    *   **Endpoint:** `PUT /alerts/{alert_id}/status`
    *   **Autenticación:** Requerida.
    *   **Cuerpo de Solicitud:** `{ "status": "acknowledged" }` o `{ "status": "resolved" }`.
*   **Obtener Resumen de Alertas:**
    *   **Endpoint:** `GET /alerts/summary`
    *   **Autenticación:** Requerida.
    *   **Query Params Sugeridos:** `tenant_id`.

#### 2.8.3. Lectura de Alertas (`alertReader`)

*   **Listar Alertas:**
    *   **Endpoint:** `GET /alerts`
    *   **Autenticación:** Requerida.
    *   **Query Params Sugeridos:** `tenant_id`, `status`, `severity`, `date_from`, `date_to`, `page`, `limit`.

---

### 2.9. Gestión de Roles y Permisos (`roleManagement`)

*   **Listar Roles:** `GET /roles` (Auth: Requerida)
*   **Crear Rol:** `POST /roles` (Auth: Requerida)
    *   Cuerpo: `{ "name": "Auditor", "tenant_id": "...", "permissions": ["VIEW_DOCUMENTS", "VIEW_REPORTS"] }`
*   **Obtener Rol:** `GET /roles/{role_id}` (Auth: Requerida)
*   **Actualizar Rol:** `PUT /roles/{role_id}` (Auth: Requerida)
*   **Eliminar Rol:** `DELETE /roles/{role_id}` (Auth: Requerida)
*   **Listar Permisos (Disponibles para asignar a roles):** `GET /permissions` (Auth: Requerida)
*   **Listar Permisos del Sistema (Todos los posibles):** `GET /permissions/system` (Auth: Requerida)
*   **Asignar Rol a Usuario:** `POST /user-roles` (Auth: Requerida)
    *   Cuerpo: `{ "user_id": "...", "role_id": "..." }`
*   **Listar Roles de Usuario:** `GET /user-roles` (Auth: Requerida)
    *   Query Params: `user_id` o `role_id`.
*   **Eliminar Rol de Usuario:** `DELETE /user-roles/{id}` (Auth: Requerida, donde `id` es el ID de la asignación)
*   **Asignar Permiso a Rol (No estándar si los permisos se definen en la creación del rol, pero disponible):** `POST /role-permissions` (Auth: Requerida)
*   **Listar Permisos de Rol:** `GET /role-permissions` (Auth: Requerida)
    *   Query Params: `role_id`.
*   **Eliminar Permiso de Rol:** `DELETE /role-permissions/{id}` (Auth: Requerida, donde `id` es el ID de la asignación)
*   **Obtener Mis Permisos (Usuario autenticado):** `GET /my-permissions` (Auth: Requerida)

---

### 2.10. Estadísticas y Reportes

#### 2.10.1. Recolección de Métricas (`metricsCollector`)
*   **Endpoint:** `POST /stats/collect`
*   **Autenticación:** Requerida (Cognito).
*   **Descripción:** Endpoint para forzar la recolección de métricas (generalmente se ejecuta por schedule).
*   **Uso Frontend:** Poco probable, más para administración o testing.

#### 2.10.2. Generación de Reportes (`reportGenerator`)
*   **Generar Reporte:** `POST /reports/generate` (Auth: Requerida)
    *   Cuerpo: `{ "report_type": "usage_summary", "tenant_id": "...", "params": { "month": "2023-10" } }`
*   **Listar Reportes Generados:** `GET /reports` (Auth: Requerida)
    *   Query: `tenant_id`, `status`.
*   **Obtener Reporte Específico:** `GET /reports/{report_id}` (Auth: Requerida)
*   **Programar Generación de Reporte:** `POST /reports/schedule` (Auth: Requerida)
*   **Listar Programaciones de Reportes:** `GET /reports/schedules` (Auth: Requerida)
*   **Eliminar Programación de Reporte:** `DELETE /reports/schedules/{schedule_id}` (Auth: Requerida)

#### 2.10.3. API de Estadísticas (`statsManager` ahora usando `statistics_api.py`)
*   **Autenticación:** Todos requieren Cognito.
*   **Query Params Comunes:** `tenant_id` (a menudo obligatorio).
*   **Endpoints:**
    *   `GET /stats/summary`: Resumen general de estadísticas del tenant.
    *   `GET /stats/documents`: Estadísticas detalladas de documentos (ej. conteos por estado, tipo, periodo). Query: `period` (day, week, month, year).
    *   `GET /stats/users`: Estadísticas de usuarios (ej. conteos por rol, estado, actividad).
    *   `GET /stats/alerts`: Estadísticas sobre alertas (ej. total, activas, por severidad). *(Función placeholder actualmente)*.
    *   `GET /stats/processing`: Estadísticas de procesamiento de documentos (ej. tiempos promedio, distribución). Query: `period`.
    *   `GET /stats/storage`: Estadísticas de almacenamiento (ej. uso total, por tipo de archivo, límites).
    *   `GET /stats/critical-documents`: Documentos críticos (ej. próximos a vencer). Query: `limit`.
    *   `GET /stats/trends`: Tendencias de métricas clave (documentos, usuarios, almacenamiento) a lo largo del tiempo. Query: `metric` (documents, users, storage), `period`.
    *   `GET /stats/key-dates`: Próximas fechas clave (vencimientos, renovaciones). Query: `days` (hacia el futuro), `limit`.
    *   `GET /stats/risks`: Estadísticas de riesgos. *(Función placeholder actualmente)*.

---

Este documento es una guía inicial. Detalles específicos sobre los campos exactos en los cuerpos de solicitud/respuesta y comportamientos complejos pueden requerir consultar la documentación a nivel de código de los handlers Lambda o especificaciones más detalladas si están disponibles. 