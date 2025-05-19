# Documentación Unificada de la API DocPilot v3

Esta guía unifica y resume toda la información relevante para el uso de la API DocPilot v3, orientada a desarrolladores frontend y testers.

---

## 1. Información General

### 1.1. URL Base
La URL base de la API depende del entorno desplegado. Ejemplo:
```
https://<api-id>.execute-api.eu-west-1.amazonaws.com/dev
```

### 1.2. Autenticación
- **Cognito User Pools**: La mayoría de los endpoints requieren autenticación mediante un token JWT de Cognito.
- Incluye el token en el header:
  ```
  Authorization: Bearer <jwt_token>
  ```
- Algunos endpoints públicos (onboarding, verificación de email) no requieren autenticación.

### 1.3. Cabeceras Comunes
- `Authorization`: Obligatoria para endpoints protegidos.
- `x-tenant-id`, `x-user-id`: Requeridas en muchos endpoints para identificar el tenant y usuario.
- `Content-Type: application/json`: Para POST/PUT.

### 1.4. Formato de Solicitudes y Respuestas
- Todas las solicitudes POST/PUT deben enviar JSON.
- Las respuestas serán en JSON.

### 1.5. Manejo de Errores
- Los errores devuelven JSON con un mensaje descriptivo:
  ```json
  { "error": "Mensaje descriptivo" }
  ```

---

## 2. Endpoints Principales

### 2.1. Carga de Documentos

#### Generar URL Prefirmada
- **GET** `/generate-url`
- **Headers:** Authorization, x-tenant-id, x-user-id
- **Query:** filename
- **Respuesta:**
  ```json
  { "uploadUrl": "url_prefirmada_s3", "objectKey": "tenant_id/user_id/filename.ext" }
  ```

#### Confirmar Subida
- **POST** `/confirm-upload`
- **Headers:** Authorization, x-tenant-id, x-user-id
- **Body:**
  ```json
  { "objectKey": "tenant_id/user_id/filename.ext" }
  ```
- **Respuesta:**
  ```json
  { "message": "Upload confirmed", "document_id": "id_documento" }
  ```

### 2.2. Gestión de Tenants

- **GET** `/tenants` — Listar tenants
- **POST** `/tenants` — Crear tenant
- **GET** `/tenants/{tenant_id}` — Detalles de un tenant
- **PUT** `/tenants/{tenant_id}` — Actualizar tenant
- **DELETE** `/tenants/{tenant_id}` — Eliminar tenant
- **GET** `/tenant-plans` — Listar planes
- **GET** `/tenants/{tenant_id}/usage` — Uso del tenant
- **PUT** `/tenants/{tenant_id}/plan` — Actualizar plan

**Ejemplo crear tenant:**
```json
{
  "name": "Nombre del Tenant",
  "email_admin": "admin@tenant.com",
  "plan_id": "plan_basico"
}
```

### 2.3. Onboarding y Verificación

- **POST** `/tenants/onboard` — Onboarding público
- **POST** `/tenants/onboard/admin` — Onboarding admin
- **GET** `/tenants/onboard/status` — Estado del onboarding
- **GET** `/tenants/verify-email` — Verificación de email (público)

### 2.4. Gestión de Usuarios

- **GET** `/users` — Listar usuarios (por tenant)
- **POST** `/users` — Crear usuario
- **GET** `/users/{user_id}` — Detalles de usuario
- **PUT** `/users/{user_id}` — Actualizar usuario
- **DELETE** `/users/{user_id}` — Eliminar usuario

**Ejemplo crear usuario:**
```json
{
  "email": "nuevo.usuario@tenant.com",
  "name": "Nombre del Usuario",
  "role_id": "id_rol",
  "tenant_id": "id_tenant"
}
```

### 2.5. Gestión de Documentos

- **GET** `/documents` — Listar documentos
- **GET** `/documents/{id}` — Detalles de documento
- **DELETE** `/documents/{id}` — Eliminar documento
- **GET** `/documents/{id}/view` — URL de visualización
- **GET** `/documents/{id}/summary` — Resumen IA
- **POST** `/documents/check-duplicate` — Verificar duplicado
- **POST** `/documents/handle-duplicate` — Gestionar duplicado

### 2.6. Auditoría

- **POST** `/audit/log` — Registrar evento
- **POST** `/audit/export` — Exportar logs
- **GET** `/audit/logs` — Listar logs

### 2.7. Configuración de Email (SES)

- **POST** `/email/domain` — Configurar dominio
- **GET** `/email/domain/status` — Estado dominio
- **POST** `/email/receipt-rule` — Crear regla de recepción
- **GET** `/email/domains` — Listar dominios
- **DELETE** `/email/domain/{tenant_id}/{domain}` — Eliminar dominio

### 2.8. Alertas y Notificaciones

- **POST** `/alerts/rules` — Crear regla de alerta
- **GET** `/alerts/rules` — Listar reglas
- **GET** `/alerts/rules/{rule_id}` — Detalles de regla
- **PUT** `/alerts/rules/{rule_id}` — Actualizar regla
- **DELETE** `/alerts/rules/{rule_id}` — Eliminar regla
- **POST** `/alerts/rules/validate` — Validar regla
- **POST** `/alerts/notify` — Notificar alerta
- **POST** `/alerts/preferences` — Crear/actualizar preferencias
- **GET** `/alerts/preferences` — Obtener preferencias
- **POST** `/alerts/process` — Procesar alerta
- **GET** `/alerts/{alert_id}` — Detalles de alerta
- **PUT** `/alerts/{alert_id}/status` — Actualizar estado
- **GET** `/alerts/summary` — Resumen de alertas
- **GET** `/alerts` — Listar alertas

### 2.9. Roles y Permisos

- **GET** `/roles` — Listar roles
- **POST** `/roles` — Crear rol
- **GET** `/roles/{role_id}` — Detalles de rol
- **PUT** `/roles/{role_id}` — Actualizar rol
- **DELETE** `/roles/{role_id}` — Eliminar rol
- **GET** `/permissions` — Listar permisos
- **GET** `/permissions/system` — Permisos del sistema
- **POST** `/user-roles` — Asignar rol a usuario
- **GET** `/user-roles` — Listar roles de usuario
- **DELETE** `/user-roles/{id}` — Eliminar asignación usuario-rol
- **POST** `/role-permissions` — Asignar permiso a rol
- **GET** `/role-permissions` — Listar permisos de rol
- **DELETE** `/role-permissions/{id}` — Eliminar permiso de rol
- **GET** `/my-permissions` — Permisos del usuario autenticado

### 2.10. Estadísticas y Reportes

- **POST** `/stats/collect` — Recolectar métricas
- **POST** `/reports/generate` — Generar reporte
- **GET** `/reports` — Listar reportes
- **GET** `/reports/{report_id}` — Obtener reporte
- **POST** `/reports/schedule` — Programar reporte
- **GET** `/reports/schedules` — Listar programaciones
- **DELETE** `/reports/schedules/{schedule_id}` — Eliminar programación
- **GET** `/stats/summary` — Resumen de estadísticas
- **GET** `/stats/documents` — Estadísticas de documentos
- **GET** `/stats/users` — Estadísticas de usuarios
- **GET** `/stats/alerts` — Estadísticas de alertas
- **GET** `/stats/processing` — Estadísticas de procesamiento
- **GET** `/stats/storage` — Estadísticas de almacenamiento
- **GET** `/stats/critical-documents` — Documentos críticos
- **GET** `/stats/trends` — Tendencias
- **GET** `/stats/key-dates` — Fechas clave
- **GET** `/stats/risks` — Riesgos

---

## 3. Notas y Consejos

- **Cuidado:** Muchos endpoints requieren cabeceras personalizadas (`x-tenant-id`, `x-user-id`).
- **Tokens:** Usa siempre el token JWT de Cognito para endpoints protegidos.
- **Errores:** Si recibes un 401/403, revisa el token y las cabeceras.
- **Pruebas:** Puedes usar Postman, Insomnia o curl para probar los endpoints.

---

¿Dudas o problemas? Contacta al equipo backend. 