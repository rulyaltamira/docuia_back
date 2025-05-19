# Documentación de la API DocPilot v3

Este documento describe los endpoints de la API para el backend de DocPilot v3, basado en la configuración de `serverless.yml`.

**URL Base:** La URL base de la API dependerá del entorno (stage) desplegado. Se puede encontrar en los outputs de Serverless después del despliegue (generalmente algo como `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>`).

**Autenticación:** La mayoría de los endpoints requieren autenticación a través de Amazon Cognito. Las solicitudes deben incluir un encabezado `Authorization` con el token ID de Cognito válido (`Authorization: Bearer <token_id>`). Algunos endpoints también pueden requerir encabezados personalizados como `x-tenant-id` y `x-user-id`, según el contexto de la operación.

**CORS:** La configuración CORS está habilitada (`origin: '*'`) para la mayoría de los endpoints que exponen un método HTTP, permitiendo solicitudes desde cualquier origen en el navegador. Se permiten varios encabezados comunes y personalizados.

---

## Endpoints

### Generación de URL de Carga (`/generate-url`)

*   **Método:** `GET`
*   **Path:** `/generate-url`
*   **Descripción:** Genera una URL prefirmada de S3 para permitir la subida segura de un documento al bucket principal.
*   **Autenticación:** Cognito User Pools.
*   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
*   **Query Params (Posibles):** `filename` (nombre del archivo a subir).
*   **Respuesta Exitosa:** JSON con la URL prefirmada y posiblemente el object key.
    ```json
    {
      "uploadUrl": "https://...",
      "objectKey": "tenant_id/user_id/filename.ext"
    }
    ```

### Confirmación de Carga (`/confirm-upload`)

*   **Método:** `POST`
*   **Path:** `/confirm-upload`
*   **Descripción:** Confirma que un documento ha sido subido correctamente a S3 usando la URL prefirmada. Esto podría disparar el procesamiento del documento.
*   **Autenticación:** Cognito User Pools.
*   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
*   **Cuerpo de Solicitud (Posible):** JSON indicando el object key del archivo subido.
    ```json
    {
      "objectKey": "tenant_id/user_id/filename.ext"
    }
    ```
*   **Respuesta Exitosa:** Mensaje de confirmación.

### Gestión de Tenants (`/tenants`)

*   **Listar Tenants:**
    *   **Método:** `GET`
    *   **Path:** `/tenants`
    *   **Descripción:** Obtiene una lista de tenants.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
*   **Crear Tenant:**
    *   **Método:** `POST`
    *   **Path:** `/tenants`
    *   **Descripción:** Crea un nuevo tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
    *   **Cuerpo de Solicitud:** Datos del tenant.
*   **Obtener Tenant:**
    *   **Método:** `GET`
    *   **Path:** `/tenants/{tenant_id}`
    *   **Descripción:** Obtiene los detalles de un tenant específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
*   **Actualizar Tenant:**
    *   **Método:** `PUT`
    *   **Path:** `/tenants/{tenant_id}`
    *   **Descripción:** Actualiza los detalles de un tenant específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
    *   **Cuerpo de Solicitud:** Datos actualizados del tenant.
*   **Eliminar Tenant:**
    *   **Método:** `DELETE`
    *   **Path:** `/tenants/{tenant_id}`
    *   **Descripción:** Elimina un tenant específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
*   **Listar Planes de Tenant:**
    *   **Método:** `GET`
    *   **Path:** `/tenant-plans`
    *   **Descripción:** Obtiene los planes disponibles para tenants.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
*   **Obtener Uso de Tenant:**
    *   **Método:** `GET`
    *   **Path:** `/tenants/{tenant_id}/usage`
    *   **Descripción:** Obtiene las métricas de uso para un tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
*   **Actualizar Plan de Tenant:**
    *   **Método:** `PUT`
    *   **Path:** `/tenants/{tenant_id}/plan`
    *   **Descripción:** Actualiza el plan de un tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
    *   **Cuerpo de Solicitud:** Nuevo plan.

### Onboarding de Tenants (`/tenants/onboard`)

*   **Iniciar Onboarding:**
    *   **Método:** `POST`
    *   **Path:** `/tenants/onboard`
    *   **Descripción:** Inicia el proceso de onboarding para un nuevo tenant (posiblemente público).
    *   **Autenticación:** Ninguna (abierto).
    *   **Cuerpo de Solicitud:** Información inicial del tenant.
*   **Onboarding Admin:**
    *   **Método:** `POST`
    *   **Path:** `/tenants/onboard/admin`
    *   **Descripción:** Proceso de onboarding iniciado por un administrador.
    *   **Autenticación:** Ninguna (abierto).
    *   **Cuerpo de Solicitud:** Información del tenant y del admin inicial.
*   **Estado del Onboarding:**
    *   **Método:** `GET`
    *   **Path:** `/tenants/onboard/status`
    *   **Descripción:** Verifica el estado del proceso de onboarding (requiere identificador).
    *   **Autenticación:** Ninguna (abierto).
    *   **Query Params:** Identificador del proceso de onboarding.

### Verificación de Email (`/tenants/verify-email`)

*   **Método:** `GET`
*   **Path:** `/tenants/verify-email`
*   **Descripción:** Endpoint al que se redirige al usuario desde el enlace de verificación de email. Procesa la verificación.
*   **Autenticación:** Ninguna (abierto, validado por token en query params).
*   **Query Params:** Token de verificación, user ID, etc.

### Gestión de Usuarios (`/users`)

*   **Listar Usuarios:**
    *   **Método:** `GET`
    *   **Path:** `/users`
    *   **Descripción:** Obtiene una lista de usuarios (probablemente dentro de un tenant).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Crear Usuario:**
    *   **Método:** `POST`
    *   **Path:** `/users`
    *   **Descripción:** Crea un nuevo usuario dentro de un tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Datos del usuario (email, rol, etc.).
*   **Obtener Usuario:**
    *   **Método:** `GET`
    *   **Path:** `/users/{user_id}`
    *   **Descripción:** Obtiene los detalles de un usuario específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Actualizar Usuario:**
    *   **Método:** `PUT`
    *   **Path:** `/users/{user_id}`
    *   **Descripción:** Actualiza los detalles de un usuario específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Datos actualizados del usuario.
*   **Eliminar Usuario:**
    *   **Método:** `DELETE`
    *   **Path:** `/users/{user_id}`
    *   **Descripción:** Desactiva o elimina un usuario específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.

### Gestión de Documentos (`/documents`)

*   **Listar Documentos:**
    *   **Método:** `GET`
    *   **Path:** `/documents`
    *   **Descripción:** Obtiene una lista de documentos para el tenant/usuario.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
*   **Obtener Documento:**
    *   **Método:** `GET`
    *   **Path:** `/documents/{id}`
    *   **Descripción:** Obtiene metadatos de un documento específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
*   **Eliminar Documento:**
    *   **Método:** `DELETE`
    *   **Path:** `/documents/{id}`
    *   **Descripción:** Elimina un documento específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
*   **Ver Documento:**
    *   **Método:** `GET`
    *   **Path:** `/documents/{id}/view`
    *   **Descripción:** Obtiene una URL prefirmada para ver/descargar el contenido del documento.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
*   **Obtener Resumen Documento:**
    *   **Método:** `GET`
    *   **Path:** `/documents/{id}/summary`
    *   **Descripción:** Obtiene el resumen generado por IA para el documento.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.

### Auditoría (`/audit`)

*   **Registrar Evento:**
    *   **Método:** `POST`
    *   **Path:** `/audit/log`
    *   **Descripción:** Registra un evento de auditoría (probablemente llamado internamente).
    *   **Autenticación:** Ninguna (o interna).
    *   **Cuerpo de Solicitud:** Detalles del evento.
*   **Exportar Logs:**
    *   **Método:** `POST`
    *   **Path:** `/audit/export`
    *   **Descripción:** Inicia un trabajo para exportar logs de auditoría.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Criterios de exportación (rango de fechas, etc.).
*   **Listar Logs:**
    *   **Método:** `GET`
    *   **Path:** `/audit/logs`
    *   **Descripción:** Obtiene una lista de eventos de auditoría recientes.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Query Params:** Filtros (fecha, usuario, tipo de evento).

### Gestión de Duplicados (`/documents/check-duplicate`, `/documents/handle-duplicate`)

*   **Verificar Duplicado:**
    *   **Método:** `POST`
    *   **Path:** `/documents/check-duplicate`
    *   **Descripción:** Verifica si un documento recién subido (o por subir) es un duplicado de uno existente.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Hash o identificador del contenido del documento.
*   **Gestionar Duplicado:**
    *   **Método:** `POST`
    *   **Path:** `/documents/handle-duplicate`
    *   **Descripción:** Indica la acción a tomar si se detecta un duplicado (e.g., reemplazar, ignorar, versionar).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Identificador del documento y acción deseada.

### Configuración de Email/SES (`/email`)

*   **Configurar Dominio:**
    *   **Método:** `POST`
    *   **Path:** `/email/domain`
    *   **Descripción:** Inicia la configuración (verificación) de un dominio en SES para un tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Nombre del dominio.
*   **Estado del Dominio:**
    *   **Método:** `GET`
    *   **Path:** `/email/domain/status`
    *   **Descripción:** Verifica el estado de verificación del dominio en SES.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Query Params:** Nombre del dominio.
*   **Crear Regla de Recepción:**
    *   **Método:** `POST`
    *   **Path:** `/email/receipt-rule`
    *   **Descripción:** Crea una regla de recepción en SES para dirigir correos entrantes a la función `emailHandler`.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Configuración de la regla (dominio, etc.).
*   **Listar Dominios:**
    *   **Método:** `GET`
    *   **Path:** `/email/domains`
    *   **Descripción:** Lista los dominios configurados para el tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Eliminar Dominio:**
    *   **Método:** `DELETE`
    *   **Path:** `/email/domain/{tenant_id}/{domain}`
    *   **Descripción:** Elimina la configuración de un dominio en SES para un tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.

### Gestión de Reglas de Alerta (`/alerts/rules`)

*   **Crear Regla:**
    *   **Método:** `POST`
    *   **Path:** `/alerts/rules`
    *   **Descripción:** Crea una nueva regla de alerta.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Definición de la regla (condición, tipo, etc.).
*   **Listar Reglas:**
    *   **Método:** `GET`
    *   **Path:** `/alerts/rules`
    *   **Descripción:** Obtiene las reglas de alerta definidas.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Obtener Regla:**
    *   **Método:** `GET`
    *   **Path:** `/alerts/rules/{rule_id}`
    *   **Descripción:** Obtiene los detalles de una regla específica.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Actualizar Regla:**
    *   **Método:** `PUT`
    *   **Path:** `/alerts/rules/{rule_id}`
    *   **Descripción:** Actualiza una regla de alerta existente.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Definición actualizada de la regla.
*   **Eliminar Regla:**
    *   **Método:** `DELETE`
    *   **Path:** `/alerts/rules/{rule_id}`
    *   **Descripción:** Elimina una regla de alerta.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Validar Regla:**
    *   **Método:** `POST`
    *   **Path:** `/alerts/rules/validate`
    *   **Descripción:** Valida la sintaxis o lógica de una definición de regla sin crearla.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Definición de la regla a validar.

### Gestión de Alertas y Notificaciones (`/alerts`)

*   **Notificar Alerta:**
    *   **Método:** `POST`
    *   **Path:** `/alerts/notify`
    *   **Descripción:** Endpoint para recibir notificaciones (posiblemente internas) y crear/enviar alertas.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
    *   **Cuerpo de Solicitud:** Detalles del evento que dispara la alerta.
*   **Gestionar Preferencias:**
    *   **Método:** `POST`
    *   **Path:** `/alerts/preferences`
    *   **Descripción:** Crea o actualiza las preferencias de notificación de alertas para un usuario.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-user-id`.
    *   **Cuerpo de Solicitud:** Preferencias del usuario (canales, frecuencia, etc.).
*   **Obtener Preferencias:**
    *   **Método:** `GET`
    *   **Path:** `/alerts/preferences`
    *   **Descripción:** Obtiene las preferencias de notificación de alertas del usuario actual.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-user-id`.
*   **Procesar Alerta:**
    *   **Método:** `POST`
    *   **Path:** `/alerts/process`
    *   **Descripción:** Procesa una alerta generada (posiblemente invocado por `scheduledAlertChecker`).
    *   **Autenticación:** Cognito User Pools (o IAM si es invocado internamente).
    *   **Encabezados Requeridos:** `Authorization`.
    *   **Cuerpo de Solicitud:** ID de la alerta o detalles del evento.
*   **Obtener Alerta:**
    *   **Método:** `GET`
    *   **Path:** `/alerts/{alert_id}`
    *   **Descripción:** Obtiene los detalles de una alerta específica.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Actualizar Estado Alerta:**
    *   **Método:** `PUT`
    *   **Path:** `/alerts/{alert_id}/status`
    *   **Descripción:** Actualiza el estado de una alerta (e.g., vista, resuelta).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.
    *   **Cuerpo de Solicitud:** Nuevo estado.
*   **Resumen de Alertas:**
    *   **Método:** `GET`
    *   **Path:** `/alerts/summary`
    *   **Descripción:** Obtiene un resumen de las alertas (e.g., número de alertas activas por severidad).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Listar Alertas:**
    *   **Método:** `GET`
    *   **Path:** `/alerts`
    *   **Descripción:** Lista las alertas generadas, con filtros opcionales.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Query Params:** Filtros (estado, severidad, fecha, regla, etc.).

### Gestión de Roles y Permisos (`/roles`, `/permissions`, `/user-roles`, `/role-permissions`, `/my-permissions`)

*   **Listar Roles:**
    *   **Método:** `GET`
    *   **Path:** `/roles`
    *   **Descripción:** Obtiene los roles definidos en el sistema o para el tenant.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Crear Rol:**
    *   **Método:** `POST`
    *   **Path:** `/roles`
    *   **Descripción:** Crea un nuevo rol.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Nombre y descripción del rol.
*   **Obtener Rol:**
    *   **Método:** `GET`
    *   **Path:** `/roles/{role_id}`
    *   **Descripción:** Obtiene detalles de un rol específico.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Actualizar Rol:**
    *   **Método:** `PUT`
    *   **Path:** `/roles/{role_id}`
    *   **Descripción:** Actualiza un rol existente.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Datos actualizados del rol.
*   **Eliminar Rol:**
    *   **Método:** `DELETE`
    *   **Path:** `/roles/{role_id}`
    *   **Descripción:** Elimina un rol.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Listar Permisos (Asignables a Roles):**
    *   **Método:** `GET`
    *   **Path:** `/permissions`
    *   **Descripción:** Obtiene la lista de permisos que se pueden asignar a los roles.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Listar Permisos del Sistema:**
    *   **Método:** `GET`
    *   **Path:** `/permissions/system`
    *   **Descripción:** Obtiene todos los permisos definidos en el sistema (informativo).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`.
*   **Asignar Rol a Usuario:**
    *   **Método:** `POST`
    *   **Path:** `/user-roles`
    *   **Descripción:** Asigna un rol a un usuario.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** `user_id`, `role_id`.
*   **Listar Roles de Usuario:**
    *   **Método:** `GET`
    *   **Path:** `/user-roles`
    *   **Descripción:** Obtiene los roles asignados a usuarios (permite filtrar por usuario o rol).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Query Params:** `user_id`, `role_id`.
*   **Eliminar Asignación Usuario-Rol:**
    *   **Método:** `DELETE`
    *   **Path:** `/user-roles/{id}`
    *   **Descripción:** Elimina la asignación de un rol a un usuario.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Asignar Permiso a Rol:**
    *   **Método:** `POST`
    *   **Path:** `/role-permissions`
    *   **Descripción:** Asigna un permiso a un rol.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** `role_id`, `permission_code`.
*   **Listar Permisos de Rol:**
    *   **Método:** `GET`
    *   **Path:** `/role-permissions`
    *   **Descripción:** Obtiene los permisos asignados a roles (permite filtrar por rol o permiso).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Query Params:** `role_id`, `permission_code`.
*   **Eliminar Asignación Rol-Permiso:**
    *   **Método:** `DELETE`
    *   **Path:** `/role-permissions/{id}`
    *   **Descripción:** Elimina la asignación de un permiso a un rol.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Obtener Mis Permisos:**
    *   **Método:** `GET`
    *   **Path:** `/my-permissions`
    *   **Descripción:** Obtiene la lista consolidada de permisos del usuario autenticado, basada en sus roles.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`, `x-user-id`.

### Estadísticas y Reportes (`/stats`, `/reports`)

*   **Recolectar Métricas:**
    *   **Método:** `POST`
    *   **Path:** `/stats/collect`
    *   **Descripción:** Endpoint para forzar la recolección de métricas (normalmente se ejecuta programado).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Generar Reporte:**
    *   **Método:** `POST`
    *   **Path:** `/reports/generate`
    *   **Descripción:** Endpoint para forzar la generación de un reporte (normalmente se ejecuta programado).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Tipo de reporte, parámetros.
*   **Listar Reportes:**
    *   **Método:** `GET`
    *   **Path:** `/reports`
    *   **Descripción:** Obtiene una lista de los reportes generados.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Obtener Reporte:**
    *   **Método:** `GET`
    *   **Path:** `/reports/{report_id}`
    *   **Descripción:** Obtiene un reporte específico (posiblemente una URL para descargarlo).
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Programar Reporte:**
    *   **Método:** `POST`
    *   **Path:** `/reports/schedule`
    *   **Descripción:** Crea una programación para generar un reporte periódicamente.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Cuerpo de Solicitud:** Configuración de la programación (tipo, frecuencia, destinatarios).
*   **Listar Programaciones:**
    *   **Método:** `GET`
    *   **Path:** `/reports/schedules`
    *   **Descripción:** Obtiene las programaciones de reportes existentes.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Eliminar Programación:**
    *   **Método:** `DELETE`
    *   **Path:** `/reports/schedules/{schedule_id}`
    *   **Descripción:** Elimina una programación de reporte.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
*   **Obtener Estadísticas (Varios Endpoints):**
    *   **Métodos:** `GET`
    *   **Paths:**
        *   `/stats/summary`
        *   `/stats/documents`
        *   `/stats/users`
        *   `/stats/alerts`
        *   `/stats/processing`
        *   `/stats/storage`
        *   `/stats/critical-documents`
        *   `/stats/trends`
        *   `/stats/key-dates`
    *   **Descripción:** Cada endpoint devuelve un conjunto específico de estadísticas agregadas o métricas clave.
    *   **Autenticación:** Cognito User Pools.
    *   **Encabezados Requeridos:** `Authorization`, `x-tenant-id`.
    *   **Query Params:** Posibles filtros de fecha u otros parámetros específicos.

---

*Nota: Los detalles exactos de los cuerpos de solicitud y respuesta pueden variar. Esta documentación se basa en la estructura y descripciones del archivo `serverless.yml`.* 