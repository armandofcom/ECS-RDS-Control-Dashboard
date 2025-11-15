# ECS & RDS Control Dashboard (Lambda + HTML)

Panel web ligero para **listar y controlar servicios ECS y RDS** (start/stop) a través de una **AWS Lambda segura**, con autenticación y token firmado (tipo JWT).

Este README explica **todo el flujo** para que QA pueda revisarlo **sin desmontarte el tinglado**:

- Arquitectura general
- Permisos necesarios de la Lambda
- Autenticación y seguridad (login + token)
- Endpoints expuestos (ECS + RDS)
- Funcionamiento del HTML / dashboard (pestañas ECS y RDS)
- Casos de prueba recomendados

## Licencia

Este proyecto se distribuye bajo la licencia **Apache License 2.0**.  
Consulta el archivo [`LICENSE`](./LICENSE) para más detalles.

---

## 1. Arquitectura general

### Componentes

1. **AWS Lambda (`app.py`)**
   - Expone una API minimalista con endpoints para:
     - `POST /login` → genera token firmado.
     - `GET /services` → lista servicios ECS.
     - `POST /action` → start/stop de servicios ECS.
     - `GET /rds/instances` → lista instancias RDS.
     - `POST /rds/action` → start/stop de instancias RDS.
   - Se puede exponer mediante:
     - **Lambda Function URL**, o
     - **API Gateway** (HTTP API / REST API).

2. **Dashboard HTML (`index.html`)**
   - Aplicación web estática (no requiere servidor).
   - Incluye:
     - Pantalla de **login**.
     - Pestañas:
       - **ECS Services**: gestión de servicios ECS.
       - **RDS Instances**: gestión de instancias RDS.
     - Para cada pestaña:
       - Tabla con información relevante.
       - Filtros (texto, estado, cluster/engine).
       - Acciones masivas:
         - **Start** de elementos seleccionados.
         - **Stop** de elementos seleccionados.

3. **Amazon ECS**
   - La Lambda se conecta vía `boto3` para:
     - Listar clusters.
     - Listar servicios.
     - Describir servicios.
     - Modificar `desiredCount` (start/stop).

4. **Amazon RDS**
   - La Lambda se conecta vía `boto3` para:
     - Listar instancias RDS.
     - Ejecutar `StartDBInstance` / `StopDBInstance` sobre instancias soportadas.

---

## 2. Permisos e IAM de la Lambda

La Lambda necesita un rol de ejecución con permisos sobre ECS y RDS.  
Política mínima recomendada:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "ecs:UpdateService"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:StartDBInstance",
        "rds:StopDBInstance"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Nota:**  
> En producción es recomendable **restringir `Resource`** a los ARN de clusters ECS e instancias RDS concretas en las cuentas/regiones donde va a operar.

---

## 3. Configuración de la Lambda

### 3.1. Runtime y handler

- **Runtime**: `Python 3.11` o `Python 3.12`.
- **Handler**: `app.lambda_handler`  
  (asumiendo que el archivo se llama `app.py`).

### 3.2. Variables de entorno

En la consola de Lambda → **Configuration → Environment variables**:

- `DASH_USER`  
  Usuario autorizado para el panel (ej: `ops_admin`).
- `DASH_PASS`  
  Contraseña del usuario anterior.
- `JWT_SECRET`  
  **Secreto largo** para firmar el token (mínimo 32 caracteres, aleatorio).
  - Ejemplo: `a_very_long_random_secret_key_987654321`
- `JWT_TTL_SECONDS` *(opcional)*  
  Tiempo de vida del token en segundos (por defecto `1800` = 30 min).

Si `DASH_USER`, `DASH_PASS` o `JWT_SECRET` no están configurados, la Lambda devuelve error 500 cuando se intenta hacer login.

### 3.3. Exposición de la Lambda

#### Opción A: Lambda Function URL

- Crear una **Function URL** para la Lambda (HTTPS).
- Configurar:
  - **Auth type**: `NONE` (la protección se hace en la Lambda con token JWT).
  - CORS: permitir el origen desde el que servirás el HTML.
- El dashboard usará una URL tipo:

```text
https://<id>.lambda-url.<region>.on.aws
```

#### Opción B: API Gateway

- Crear un **HTTP API** o **REST API**.
- Integrarlo con la Lambda como proxy.
- Configurar rutas:
  - `POST /login`
  - `GET /services`
  - `POST /action`
  - `GET /rds/instances`
  - `POST /rds/action`
- El dashboard usará una URL tipo:

```text
https://<id>.execute-api.<region>.amazonaws.com/prod
```

> En el HTML, esa URL se define en la constante `API_BASE_URL`.

---

## 4. Endpoints de la API

La Lambda implementa un **enrutado simple** en `lambda_handler` según:

- `method` → `GET`, `POST`, `OPTIONS`
- `path` → `/`, `/login`, `/services`, `/action`, `/rds/instances`, `/rds/action`

### 4.1. `POST /login` — autenticación inicial

- **Sin token** todavía (es el único endpoint público).
- Recibe JSON:

```json
{
  "user": "ops_admin",
  "pass": "contraseña"
}
```

- Respuestas:

  - **200 OK** (credenciales válidas):

    ```json
    {
      "token": "<JWT_firmado>",
      "user": "ops_admin",
      "role": "admin",
      "expiresIn": 1800
    }
    ```

  - **401 Unauthorized** (credenciales incorrectas):

    ```json
    {
      "error": "Credenciales inválidas"
    }
    ```

  - **500 Internal Server Error** (config mal hecha):

    ```json
    {
      "error": "DASH_USER/DASH_PASS no configurados"
    }
    ```

### 4.2. Token firmado (tipo JWT)

Se genera un token HS256 tipo JWT con:

- Cabecera:

  ```json
  {
    "alg": "HS256",
    "typ": "JWT"
  }
  ```

- Payload:

  ```json
  {
    "sub": "<usuario>",
    "role": "admin",
    "iat": <timestamp_ahora>,
    "exp": <timestamp_expiración>,
    "iss": "ecs-rds-dashboard",
    "aud": "ecs-rds-dashboard-ui"
  }
  ```

- Firma: `HMAC-SHA256` con `JWT_SECRET`.

La Lambda verifica en cada petición protegida:

- Que la firma es válida.
- Que no está expirado (`exp`).
- Que `iss` y `aud` son correctos.
- Que, para operaciones sensibles (`/action`, `/rds/action`), el `role` sea `"admin"`.

### 4.3. Autorización en endpoints protegidos

Para `/services`, `/action`, `/rds/instances` y `/rds/action`, el cliente debe enviar:

```http
Authorization: Bearer <token>
```

#### Errores de autenticación/autorización

- Token ausente / inválido / expirado → **401 Unauthorized**:

  ```json
  {
    "error": "Token ausente"
  }
  ```

  ```json
  {
    "error": "Token expirado"
  }
  ```

- Rol insuficiente (si se aplicaran roles distintos a admin) → **401 Unauthorized**:

  ```json
  {
    "error": "Permisos insuficientes"
  }
  ```

---

## 5. Endpoints ECS

### 5.1. `GET /services` — listar servicios ECS

- **Protegido** → requiere `Authorization: Bearer <token>`.
- Parámetros (query string):

  - `cluster` *(opcional)* → filtra por nombre de cluster exacto.

- Ejemplo:

```bash
curl -X GET   "https://<API_BASE_URL>/services?cluster=my-ecs-cluster"   -H "Authorization: Bearer <TOKEN>"
```

- Respuesta (200 OK):

```json
{
  "services": [
    {
      "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-ecs-cluster",
      "clusterName": "my-ecs-cluster",
      "serviceArn": "arn:aws:ecs:us-east-1:123456789012:service/my-ecs-cluster/api-backend",
      "serviceName": "api-backend",
      "status": "ACTIVE",
      "desiredCount": 1,
      "runningCount": 1,
      "launchType": "FARGATE",
      "createdAt": "2025-11-15T10:25:01.123Z",
      "schedulingStrategy": "REPLICA"
    }
  ]
}
```

### 5.2. `POST /action` — start/stop servicios ECS

- **Protegido** → requiere `Authorization: Bearer <token>` con rol `"admin"`.

- Cuerpo JSON:

```json
{
  "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-ecs-cluster",
  "serviceName": "api-backend",
  "action": "stop",
  "desiredCount": 1
}
```

- `action`:
  - `"stop"` → fuerza `desiredCount = 0`.
  - `"start"` → usa:
    - `desiredCount` del cuerpo (si se envía), o
    - `1` por defecto.

- Ejemplo `stop`:

```bash
curl -X POST   "https://<API_BASE_URL>/action"   -H "Authorization: Bearer <TOKEN>"   -H "Content-Type: application/json"   -d '{
    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-ecs-cluster",
    "serviceName": "api-backend",
    "action": "stop"
  }'
```

- Respuesta (200 OK):

```json
{
  "result": {
    "clusterArn": "arn:aws:ecs:us-east-1:123456789012:cluster/my-ecs-cluster",
    "serviceName": "api-backend",
    "newDesiredCount": 0,
    "runningCount": 0,
    "status": "ACTIVE"
  }
}
```

---

## 6. Endpoints RDS

### 6.1. `GET /rds/instances` — listar instancias RDS

- **Protegido** → requiere `Authorization: Bearer <token>`.
- Parámetros (query string, opcionales):

  - `engine` → filtra por engine exacto (ej: `mysql`, `postgres`, `aurora-mysql`).
  - `status` → filtra por status exacto (ej: `available`, `stopped`).

- Ejemplo:

```bash
curl -X GET   "https://<API_BASE_URL>/rds/instances?engine=postgres&status=available"   -H "Authorization: Bearer <TOKEN>"
```

- Respuesta (200 OK):

```json
{
  "instances": [
    {
      "dbInstanceIdentifier": "mi-db-prod",
      "dbInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:mi-db-prod",
      "engine": "postgres",
      "engineVersion": "15.3",
      "dbInstanceClass": "db.t3.medium",
      "multiAZ": false,
      "availabilityZone": "us-east-1a",
      "status": "available",
      "endpoint": "mi-db-prod.xxxxxxxx.us-east-1.rds.amazonaws.com",
      "allocatedStorage": 100,
      "storageType": "gp3",
      "clusterIdentifier": null,
      "publiclyAccessible": false
    }
  ]
}
```

### 6.2. `POST /rds/action` — start/stop instancias RDS

- **Protegido** → requiere `Authorization: Bearer <token>` con rol `"admin"`.
- Cuerpo JSON:

```json
{
  "dbInstanceIdentifier": "mi-db-prod",
  "action": "stop"
}
```

- `action`:
  - `"stop"` → llama internamente a `rds.stop_db_instance`.
  - `"start"` → llama internamente a `rds.start_db_instance`.

> **Nota:**  
> No todas las instancias RDS soportan `stop/start` (ej: ciertas configuraciones Multi-AZ o Aurora).  
> Si la operación no es válida, RDS devolverá un error que la Lambda propagará como 500 con mensaje.

- Respuesta (200 OK):

```json
{
  "result": {
    "dbInstanceIdentifier": "mi-db-prod",
    "status": "stopping",
    "engine": "postgres",
    "dbInstanceClass": "db.t3.medium",
    "availabilityZone": "us-east-1a",
    "multiAZ": false
  }
}
```

---

## 7. Autenticación y seguridad

### 7.1. Capa de transporte

- Toda la comunicación se hace vía **HTTPS** (Function URL o API Gateway).
- El header `Authorization: Bearer` viaja cifrado por TLS → **no se envían credenciales en texto plano**.

### 7.2. Nada de credenciales en URLs

- **No se pasa `user/pass` en query string** ni en cada request.
- El login se hace una única vez (`POST /login`), y después solo se usa el **token**.

### 7.3. Tokens de vida corta

- El token tiene un `exp` definido por `JWT_TTL_SECONDS` (por defecto, 30 minutos).
- Una vez expirado → cualquier endpoint protegido responde **401** y el front fuerza re-login.

### 7.4. Defensa básica en profundidad

- Verificación de:
  - firma del token,
  - expiración,
  - `iss` y `aud`,
  - `role` para operaciones sensibles.
- IAM de la Lambda limitado solo a las acciones estrictamente necesarias (ECS y RDS).
- CORS controlado (en prod se recomienda sustituir `Access-Control-Allow-Origin: *` por el dominio real del dashboard).

---

## 8. Dashboard HTML (`index.html`)

### 8.1. Configuración

En el HTML hay una constante:

```js
const API_BASE_URL = "https://<tu-url-de-lambda-o-api-gw>";
```

Debe apuntar a la URL base donde está expuesta la Lambda.

### 8.2. Flujo de uso

1. **Pantalla de login**
   - Pide `usuario` + `contraseña`.
   - Hace `POST /login` a la API.
   - Si el login es correcto:
     - Guarda `token`, `user`, `role` en memoria.
     - Oculta la tarjeta de login.
     - Muestra el dashboard.
     - Carga por defecto la pestaña **ECS** (`GET /services`).

2. **Pestañas**
   - **ECS Services**:
     - Lista y controla servicios ECS (start/stop).
   - **RDS Instances**:
     - Lista y controla instancias RDS (start/stop).
   - Cambiar de pestaña no requiere re-login; reutiliza el mismo token.

### 8.3. Pestaña ECS

- Tabla con columnas:
  - Selección (checkbox),
  - Servicio,
  - Cluster,
  - Desired / Running,
  - Launch type,
  - Estado (badge "Activo"/"Parado").
- Filtros:
  - Texto (servicio/cluster).
  - Estado (`Todos`, `Con desiredCount > 0`, `Con desiredCount = 0`).
  - Nombre de cluster (select dinámico).
- Acciones:
  - `Start seleccionados` → `POST /action` con `action="start"`.
  - `Stop seleccionados` → `POST /action` con `action="stop"`.
- Otros:
  - Checkbox global para seleccionar todos los servicios filtrados.
  - Indicador de nº de servicios visibles y seleccionados.

### 8.4. Pestaña RDS

- Tabla con columnas:
  - Selección (checkbox),
  - DB Identifier,
  - Engine,
  - Clase,
  - AZ / Multi-AZ,
  - Status (badge).
- Filtros:
  - Texto (db identifier / engine).
  - Engine (select dinámico).
  - Estado:
    - `Todos`,
    - `Sólo available`,
    - `Sólo stopped`.
- Acciones:
  - `Start seleccionados` → `POST /rds/action` con `action="start"`.
  - `Stop seleccionados` → `POST /rds/action` con `action="stop"`.
- Otros:
  - Checkbox global para seleccionar todas las instancias filtradas.
  - Indicador de nº de instancias visibles y seleccionadas.

### 8.5. Gestión de sesión

- Si la API responde con **401** (token ausente/expirado):
  - El front elimina el token en memoria.
  - Oculta el dashboard.
  - Muestra de nuevo el login con mensaje de “Sesión expirada o no autorizada”.

---

## 9. Flujo completo end-to-end

1. Usuario abre `index.html` en el navegador.
2. Ve la pantalla de login.
3. Introduce `usuario` + `contraseña`.
4. El front hace `POST /login`:
   - Si ok → recibe `token` y lo guarda.
   - Si ko → muestra error.
5. Tras login:
   - Se muestra el dashboard con pestañas ECS y RDS.
   - Se carga la lista de servicios ECS (`GET /services`).
6. Al cambiar a la pestaña RDS:
   - Se llama a `GET /rds/instances`.
7. En cada pestaña:
   - El usuario puede filtrar, seleccionar y lanzar **start/stop**.
   - Cada acción genera llamadas `POST /action` (ECS) o `POST /rds/action` (RDS).
   - Tras las acciones, se recarga la lista correspondiente.

---

## 10. Casos de prueba recomendados para QA

### 10.1. Autenticación

- `GET /services` sin `Authorization`:
  - **401 Unauthorized**.
- `POST /login` con credenciales incorrectas:
  - **401** con `{"error": "Credenciales inválidas"}`.
- `POST /login` con credenciales correctas:
  - **200** con `token`, `user`, `role`, `expiresIn`.

### 10.2. Token

- Usar un token correcto en `GET /services` y `GET /rds/instances`:
  - **200** y datos correspondientes.
- Modificar 1 carácter del token:
  - **401** (firma inválida).
- Esperar más del tiempo `JWT_TTL_SECONDS` y reutilizar el token:
  - **401** (token expirado).

### 10.3. ECS

- Sin parámetro `cluster`:
  - Lista servicios de todos los clusters.
- Con `cluster=<nombre>`:
  - Lista sólo servicios de ese cluster.
- `POST /action` con `action="stop"` sobre servicio con `desiredCount > 0`:
  - `newDesiredCount` debe ser `0`.
- `POST /action` con `action="start"` sobre servicio parado:
  - `newDesiredCount` debe reflejar el valor enviado (por defecto `1`).
- `POST /action` sin token:
  - **401**.
- `POST /action` con cuerpo incompleto:
  - **400** con mensaje de campos obligatorios.

### 10.4. RDS

- `GET /rds/instances` sin filtros:
  - Lista todas las instancias accesibles.
- `GET /rds/instances?engine=postgres&status=available`:
  - Lista sólo instancias que cumplan ambos criterios.
- `POST /rds/action` con `action="stop"` sobre una instancia que admite stop:
  - Status devuelto debe pasar a `stopping` / `stopped` según el flujo de RDS.
- `POST /rds/action` con `action="start"` sobre instancia `stopped`:
  - Status devuelto debe ser `starting` / `available` según el flujo.
- `POST /rds/action` sobre instancia que **no admite** stop:
  - RDS devolverá error; la Lambda lo propagará como **500** con mensaje en JSON.
- `POST /rds/action` sin token:
  - **401**.

### 10.5. UI / Dashboard

- Antes de login:
  - No se deben mostrar datos de ECS ni RDS.
- Después de login:
  - Pestaña ECS:
    - Lista servicios,
    - Filtros y selección global funcionan.
  - Pestaña RDS:
    - Lista instancias,
    - Filtros y selección global funcionan.
- Al expirar el token:
  - El dashboard deja de funcionar y el usuario es redirigido al login.

---

## 11. Mejores prácticas adicionales (opcional para futuro)

- Reemplazar `Access-Control-Allow-Origin: "*"` por el dominio concreto del panel (ej: `https://ops.miempresa.com`).
- Colocar la API detrás de:
  - **API Gateway** + **WAF**,
  - Throttling / rate limiting,
  - Logs centralizados.
- Integrar con IdP corporativo (Cognito, Azure AD, Okta) para SSO y MFA.
- Añadir auditoría:
  - Logging de `sub` (usuario) + acción + target (ECS servicio o RDS instancia) en CloudWatch o SIEM.

---

## 12. Resumen

Este sistema implementa un panel interno para gestión de:

- **Servicios ECS** (start/stop vía `desiredCount`).
- **Instancias RDS** (start/stop vía `StartDBInstance` / `StopDBInstance`).

Con:

- Autenticación basada en **HTTPS + token firmado de vida corta**.
- Permisos IAM reducidos a lo estrictamente necesario.
- UI con login, pestañas, filtros, acciones masivas y feedback visual.

Con este README, QA tiene trazado todo el comportamiento esperado, tanto de backend (Lambda) como de frontend (HTML), incluyendo las consideraciones de seguridad y los casos de prueba recomendados para ECS **y** RDS.
