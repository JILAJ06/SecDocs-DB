# SecDocs · Base de datos

Esquema y migraciones de PostgreSQL 16 para **SecDocs**, bóveda digital para guardar y compartir documentos confidenciales.
Proyecto de Seguridad Informática, Universidad Politécnica de Chiapas.

## Repositorios del proyecto
- [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend): interfaz web (Next.js)
- [SecDocs-Backend](https://github.com/JILAJ06/SecDocs-Backend): API en Node.js/Express
- **SecDocs-DB** (este repositorio)

## Estructura
```
schema/       esquema de la base de datos
migrations/   migraciones
scripts/      utilidades
```

## Notas de seguridad
- La base de datos solo guarda las llaves de archivo (DEK) **envueltas** con la llave maestra, que vive fuera de la base de datos.
- Nunca subas contraseñas ni volcados (`*.dump`) a este repositorio.
