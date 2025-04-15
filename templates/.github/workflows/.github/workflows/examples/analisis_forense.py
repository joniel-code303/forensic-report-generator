#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de Automatización Avanzada para Generación de Reportes Técnicos

Este script permite:
1. Generar reportes técnicos legibles por humanos en formato Markdown/HTML/PDF
2. Exportar datos estructurados para análisis forense en JSON/CSV/SQLite
3. Procesar múltiples fuentes de datos
4. Incluir metadatos forenses
5. Opciones de cifrado para datos sensibles

Autor: [Tu Nombre]
Fecha: [Fecha]
Versión: 1.0
"""

import argparse
import json
import csv
import sqlite3
from datetime import datetime
import hashlib
import markdown
import pdfkit
import logging
from typing import Dict, List, Optional, Union
import sys
import os
import pytz
from jinja2 import Environment, FileSystemLoader
import yaml
from cryptography.fernet import Fernet

# Configuración inicial
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('report_generator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ForensicReportGenerator:
    """Clase principal para la generación de reportes forenses."""
    
    def __init__(self, config_file: str = 'config.yaml'):
        """Inicializa el generador de reportes con configuración."""
        self.config = self._load_config(config_file)
        self.data_sources = {}
        self.report_data = {
            'metadata': self._generate_metadata(),
            'findings': [],
            'artifacts': [],
            'timeline': [],
            'analysis': {}
        }
        self._setup_database()
        
        # Configuración de plantillas
        self.template_env = Environment(
            loader=FileSystemLoader(self.config.get('templates_dir', 'templates')),
            autoescape=True
        )
        
        # Configuración de cifrado si está habilitado
        self.crypto = None
        if self.config.get('encryption', {}).get('enabled', False):
            self._init_encryption()
    
    def _load_config(self, config_file: str) -> Dict:
        """Carga la configuración desde un archivo YAML."""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error al cargar configuración: {e}")
            raise
    
    def _generate_metadata(self) -> Dict:
        """Genera metadatos forenses para el reporte."""
        return {
            'case_id': hashlib.sha256(datetime.now().isoformat().encode()).hexdigest()[:16],
            'creation_time': datetime.now(pytz.utc).isoformat(),
            'investigator': self.config.get('investigator', 'Unknown'),
            'tools_used': [
                {'name': 'Forensic Report Generator', 'version': '1.0'},
                {'name': 'Python', 'version': sys.version.split()[0]}
            ],
            'system_info': {
                'platform': sys.platform,
                'os': os.name
            },
            'hash_algorithm': 'SHA-256'
        }
    
    def _init_encryption(self):
        """Inicializa el sistema de cifrado si está configurado."""
        try:
            key = self.config['encryption']['key']
            if key == 'auto':
                key = Fernet.generate_key()
                logger.warning("Clave de cifrado generada automáticamente. ¡Guárdala de forma segura!")
                logger.warning(f"Clave: {key.decode()}")
            self.crypto = Fernet(key)
        except Exception as e:
            logger.error(f"Error al inicializar cifrado: {e}")
            raise
    
    def _setup_database(self):
        """Configura la base de datos SQLite para almacenamiento forense."""
        self.db_conn = sqlite3.connect(self.config.get('database', ':memory:'))
        self._init_db_schema()
    
    def _init_db_schema(self):
        """Inicializa el esquema de la base de datos."""
        cursor = self.db_conn.cursor()
        
        # Tabla de metadatos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS report_metadata (
            case_id TEXT PRIMARY KEY,
            creation_time TEXT,
            investigator TEXT,
            platform TEXT,
            os TEXT
        )
        ''')
        
        # Tabla de hallazgos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            timestamp TEXT,
            category TEXT,
            description TEXT,
            severity INTEGER,
            evidence TEXT,
            FOREIGN KEY (case_id) REFERENCES report_metadata (case_id)
        )
        ''')
        
        # Tabla de artefactos
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            artifact_type TEXT,
            source TEXT,
            content_hash TEXT,
            content BLOB,
            FOREIGN KEY (case_id) REFERENCES report_metadata (case_id)
        )
        ''')
        
        self.db_conn.commit()
    
    def add_data_source(self, name: str, data: Union[Dict, List]):
        """Añade una fuente de datos para el análisis."""
        self.data_sources[name] = data
        logger.info(f"Fuente de datos '{name}' añadida con {len(data) if isinstance(data, (list, dict)) else 1} elementos.")
    
    def analyze_data(self):
        """Realiza el análisis de los datos cargados."""
        logger.info("Iniciando análisis de datos...")
        
        # Ejemplo de análisis: buscar patrones sospechosos
        for name, data in self.data_sources.items():
            if isinstance(data, list):
                for item in data:
                    self._analyze_item(item, source=name)
            elif isinstance(data, dict):
                self._analyze_item(data, source=name)
        
        logger.info(f"Análisis completado. {len(self.report_data['findings'])} hallazgos identificados.")
    
    def _analyze_item(self, item: Dict, source: str):
        """Analiza un elemento individual de datos."""
        # Aquí iría la lógica de análisis específica
        # Este es un ejemplo simple que busca campos específicos
        
        if 'timestamp' in item:
            self.report_data['timeline'].append({
                'event': item.get('description', 'Evento sin descripción'),
                'timestamp': item['timestamp'],
                'source': source
            })
        
        # Ejemplo: detectar actividad sospechosa
        if 'event_type' in item and item['event_type'].lower() == 'error':
            finding = {
                'timestamp': item.get('timestamp', datetime.now().isoformat()),
                'category': 'Error detectado',
                'description': f"Error en {source}: {item.get('message', 'Sin mensaje')}",
                'severity': 3,  # Escala de 1 a 5
                'evidence': str(item),
                'source': source
            }
            self.report_data['findings'].append(finding)
            
            # También guardar en base de datos
            self._save_finding_to_db(finding)
    
    def _save_finding_to_db(self, finding: Dict):
        """Guarda un hallazgo en la base de datos."""
        cursor = self.db_conn.cursor()
        try:
            cursor.execute('''
            INSERT INTO findings 
            (case_id, timestamp, category, description, severity, evidence)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                self.report_data['metadata']['case_id'],
                finding['timestamp'],
                finding['category'],
                finding['description'],
                finding['severity'],
                finding['evidence']
            ))
            self.db_conn.commit()
        except Exception as e:
            logger.error(f"Error al guardar hallazgo en DB: {e}")
            self.db_conn.rollback()
    
    def generate_human_report(self, format: str = 'markdown') -> str:
        """Genera un reporte legible por humanos en el formato especificado."""
        logger.info(f"Generando reporte en formato {format.upper()}...")
        
        # Preparar datos para la plantilla
        report_context = {
            'metadata': self.report_data['metadata'],
            'findings': sorted(self.report_data['findings'], key=lambda x: x['severity'], reverse=True),
            'timeline': sorted(self.report_data['timeline'], key=lambda x: x['timestamp']),
            'generated_at': datetime.now(pytz.utc).strftime('%Y-%m-%d %H:%M:%S %Z')
        }
        
        # Seleccionar plantilla según formato
        template_file = {
            'markdown': 'report_template.md.j2',
            'html': 'report_template.html.j2'
        }.get(format.lower(), 'report_template.md.j2')
        
        try:
            template = self.template_env.get_template(template_file)
            rendered = template.render(report_context)
            
            if format.lower() == 'pdf':
                # Convertir HTML a PDF
                html = self.generate_human_report('html')
                pdfkit.from_string(html, 'report.pdf')
                return "Reporte PDF generado como 'report.pdf'"
            
            return rendered
        except Exception as e:
            logger.error(f"Error al generar reporte: {e}")
            raise
    
    def generate_forensic_export(self, format: str = 'json') -> str:
        """Genera un export estructurado para análisis forense."""
        logger.info(f"Generando export forense en formato {format.upper()}...")
        
        # Incluir metadatos adicionales para el export forense
        forensic_data = {
            **self.report_data,
            'export_metadata': {
                'export_time': datetime.now(pytz.utc).isoformat(),
                'export_format': format,
                'integrity_check': self._generate_integrity_hash()
            }
        }
        
        try:
            if format.lower() == 'json':
                output = json.dumps(forensic_data, indent=2)
                if self.crypto:
                    output = self.crypto.encrypt(output.encode()).decode()
                return output
            
            elif format.lower() == 'csv':
                # Convertir datos principales a CSV
                output = []
                # CSV para hallazgos
                findings_csv = ['timestamp,category,description,severity,source\n']
                findings_csv.extend(
                    f"{f['timestamp']},{f['category']},{f['description']},{f['severity']},{f.get('source', '')}\n"
                    for f in forensic_data['findings']
                )
                output.append(''.join(findings_csv))
                
                # CSV para timeline
                timeline_csv = ['timestamp,event,source\n']
                timeline_csv.extend(
                    f"{t['timestamp']},{t['event']},{t['source']}\n"
                    for t in forensic_data['timeline']
                )
                output.append(''.join(timeline_csv))
                
                return '\n'.join(output)
            
            elif format.lower() == 'sqlite':
                # Crear un nuevo archivo SQLite con todos los datos
                temp_db = sqlite3.connect(':memory:')
                self._export_to_sqlite(temp_db)
                return temp_db  # Devolver conexión a la base de datos
            
            else:
                raise ValueError(f"Formato no soportado: {format}")
        except Exception as e:
            logger.error(f"Error al generar export forense: {e}")
            raise
    
    def _generate_integrity_hash(self) -> str:
        """Genera un hash de integridad para los datos del reporte."""
        data_str = json.dumps(self.report_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _export_to_sqlite(self, db_conn: sqlite3.Connection):
        """Exporta todos los datos a una conexión SQLite."""
        try:
            # Exportar metadatos
            cursor = db_conn.cursor()
            
            # Crear esquema
            self._init_db_schema()
            
            # Copiar datos de la base de datos principal
            for table in ['report_metadata', 'findings', 'artifacts']:
                cursor.execute(f"ATTACH DATABASE '{self.config.get('database', ':memory:')}' AS source_db")
                cursor.execute(f"INSERT INTO {table} SELECT * FROM source_db.{table}")
                db_conn.commit()
                
        except Exception as e:
            logger.error(f"Error en export SQLite: {e}")
            raise

def main():
    """Función principal para ejecución desde línea de comandos."""
    parser = argparse.ArgumentParser(
        description='Herramienta avanzada para generación de reportes técnicos forenses',
        epilog='Ejemplos de uso:\n'
               '  report_tool.py --format html --output report.html\n'
               '  report_tool.py --forensic json --encrypt',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Argumentos principales
    parser.add_argument(
        '--format', 
        choices=['markdown', 'html', 'pdf'], 
        default='markdown',
        help='Formato del reporte legible por humanos'
    )
    parser.add_argument(
        '--forensic', 
        choices=['json', 'csv', 'sqlite'], 
        help='Genera un export para análisis forense en el formato especificado'
    )
    parser.add_argument(
        '--output', 
        default='report',
        help='Nombre base del archivo de salida (sin extensión)'
    )
    parser.add_argument(
        '--config', 
        default='config.yaml',
        help='Archivo de configuración YAML'
    )
    parser.add_argument(
        '--encrypt', 
        action='store_true',
        help='Cifrar los datos sensibles en el export forense'
    )
    parser.add_argument(
        '--data', 
        nargs='+',
        help='Archivos de datos a analizar (JSON, CSV)'
    )
    
    args = parser.parse_args()
    
    try:
        # Inicializar generador de reportes
        config = {'encryption': {'enabled': args.encrypt}}
        if args.encrypt:
            config['encryption']['key'] = 'auto'
        
        # Guardar configuración temporal si no existe el archivo
        if not os.path.exists(args.config):
            with open(args.config, 'w') as f:
                yaml.dump(config, f)
            logger.warning(f"Archivo de configuración '{args.config}' creado con valores por defecto.")
        
        report_gen = ForensicReportGenerator(args.config)
        
        # Procesar archivos de datos si se especificaron
        if args.data:
            for data_file in args.data:
                try:
                    with open(data_file, 'r') as f:
                        if data_file.endswith('.json'):
                            data = json.load(f)
                        elif data_file.endswith('.csv'):
                            data = list(csv.DictReader(f))
                        else:
                            logger.warning(f"Formato no soportado para {data_file}, omitiendo...")
                            continue
                        
                        report_gen.add_data_source(os.path.basename(data_file), data)
                except Exception as e:
                    logger.error(f"Error al procesar {data_file}: {e}")
        
        # Analizar datos
        report_gen.analyze_data()
        
        # Generar reporte legible por humanos
        human_report = report_gen.generate_human_report(args.format)
        output_file = f"{args.output}.{args.format}"
        
        with open(output_file, 'w') as f:
            f.write(human_report if isinstance(human_report, str) else str(human_report))
        
        logger.info(f"Reporte legible generado en '{output_file}'")
        
        # Generar export forense si se solicitó
        if args.forensic:
            forensic_export = report_gen.generate_forensic_export(args.forensic)
            forensic_file = f"{args.output}_forensic.{args.forensic}"
            
            if args.forensic == 'sqlite':
                # Para SQLite, forensic_export es una conexión a la base de datos
                forensic_export.backup(sqlite3.connect(forensic_file))
                forensic_export.close()
            else:
                with open(forensic_file, 'w') as f:
                    f.write(forensic_export if isinstance(forensic_export, str) else str(forensic_export))
            
            logger.info(f"Export forense generado en '{forensic_file}'")
    
    except Exception as e:
        logger.error(f"Error fatal: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
