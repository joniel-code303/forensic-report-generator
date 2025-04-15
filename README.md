# forensic-report-generator
Herramienta avanzada en Python para la generación automatizada de reportes técnicos forenses. Permite crear reportes legibles (Markdown/HTML/PDF) y exportar datos estructurados (JSON/CSV/SQLite) con metadatos forenses, cifrado opcional y análisis integrado. Ideal para investigaciones digitales, auditorías de seguridad y documentación técnica.


# Forensic Report Generator 🔍📄

Herramienta avanzada para generación automatizada de reportes forenses en Python.  
**Perfecta para investigaciones digitales, auditorías de seguridad y documentación técnica.**

## Características
- Genera reportes en **Markdown, HTML y PDF**.
- Exporta datos estructurados para análisis forense (**JSON/CSV/SQLite**).
- **Cifrado opcional** de datos sensibles (Fernet).
- Línea de tiempo automatizada y análisis de hallazgos.
- Metadatos forenses y verificaciones de integridad (SHA-256).

## Instalación
```bash
git clone https://github.com/tu-usuario/forensic-report-generator.git
cd forensic-report-generator
pip install -r requirements.txt


Uso Basico

# Generar reporte HTML con datos de ejemplo
python analisis_forense.py --format html --data examples/sample_data.json

# Exportar datos forenses a JSON cifrado
python analisis_forense.py --forensic json --encrypt






Configuración
Edita config.yaml para personalizar:


investigator: "Nombre del Investigador"
encryption:
  enabled: true
  key: "tu_clave_secreta_o_auto"






---

#### 2. `requirements.txt`


python>=3.8
pyyaml>=6.0
jinja2>=3.0
pdfkit>=1.0
cryptography>=36.0
pytz>=2022.1









---

#### 3. `.gitignore`

Python
pycache/
*.pyc
*.pyo
*.pyd

Datos sensibles
*.key
*.enc

Reportes generados
*.pdf
*.html
*.md

SQLite
*.db
*.sqlite

Entornos virtuales
venv/
.env







---

#### 4. `config.yaml` (Configuración por defecto)
```yaml
investigator: "Investigador Forense"
database: "forensic_data.db"
templates_dir: "templates"
encryption:
  enabled: false
  key: "auto"
