pipeline {
    agent any
    
    environment {
        DOCKER_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        APP_PORT = '5000'
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo '📥 Clonando repositorio...'
                git branch: 'main', 
                    url: 'https://github.com/Felipe-Droguett58/CiberSeguri-ExamenTrasversal.git'
            }
        }
        
        stage('Setup Python Environment') {
            steps {
                echo '🐍 Configurando entorno Python...'
                bat '''
                    echo Verificando Python...
                    python --version
                    
                    echo Instalando dependencias desde requirements.txt...
                    if exist requirements.txt (
                        pip install -r requirements.txt
                        echo ✅ Dependencias instaladas desde requirements.txt
                    ) else (
                        echo ⚠️ No se encontró requirements.txt
                        echo Instalando dependencias directamente...
                        pip install flask bcrypt markupsafe
                    )
                    
                    echo Dependencias instaladas correctamente
                '''
            }
        }
        
        stage('Setup Database') {
            steps {
                echo '🗄️ Creando base de datos...'
                bat '''
                    echo Creando base de datos SQLite...
                    python create_db.py
                    
                    echo Verificando base de datos creada...
                    if exist example.db (
                        echo ✅ Base de datos creada correctamente
                    ) else (
                        echo ❌ Error: No se pudo crear la base de datos
                        exit /b 1
                    )
                '''
            }
        }
        
        stage('Start Application') {
            steps {
                echo '🚀 Iniciando aplicación Flask...'
                script {
                    bat '''
                        echo Matando procesos previos de Flask...
                        taskkill /F /IM python.exe /FI "WINDOWTITLE eq Flask*" 2>nul || echo No hay procesos previos
                        
                        echo Iniciando aplicación Flask...
                        start /B python vulnerable_flask_app.py > app.log 2>&1
                        
                        echo Esperando que la aplicación inicie...
                        timeout /t 5 /nobreak >nul
                        
                        echo Verificando conexión...
                        for /L %%i in (1,1,30) do (
                            curl -s -f http://localhost:%APP_PORT% >nul 2>&1
                            if !errorlevel! equ 0 (
                                echo ✅ Aplicación iniciada correctamente en http://localhost:%APP_PORT%
                                goto :app_ready
                            )
                            echo Intentando conectar... (%%i/30)
                            timeout /t 2 /nobreak >nul
                        )
                        
                        echo ❌ No se pudo iniciar la aplicación
                        echo === LOGS DE LA APLICACIÓN ===
                        type app.log
                        exit /b 1
                        
                        :app_ready
                        echo ✅ Aplicación corriendo en http://localhost:%APP_PORT%
                    '''
                }
            }
        }
        
        stage('Run OWASP ZAP Scan') {
            steps {
                echo '🔍 Ejecutando escaneo de seguridad con OWASP ZAP...'
                script {
                    try {
                        bat '''
                            echo Creando directorio para reportes...
                            if not exist reports mkdir reports
                            
                            echo Ejecutando ZAP Baseline Scan...
                            echo Esto puede tomar varios minutos...
                            
                            docker run ^
                                -v "%cd%":/zap/wrk/:rw ^
                                %DOCKER_IMAGE% ^
                                zap-baseline.py ^
                                -t http://localhost:%APP_PORT% ^
                                -r zap_report.html ^
                                -J zap_report.json ^
                                -z "-config api.disablekey=true"
                            
                            echo Verificando reportes generados...
                            if exist zap_report.html (
                                copy zap_report.html reports\\ >nul
                                echo ✅ Reporte HTML generado
                            ) else (
                                echo ⚠️ No se generó el reporte HTML
                            )
                            
                            if exist zap_report.json (
                                copy zap_report.json reports\\ >nul
                                echo ✅ Reporte JSON generado
                            ) else (
                                echo ⚠️ No se generó el reporte JSON
                            )
                        '''
                    } catch (Exception e) {
                        echo "⚠️ El escaneo de ZAP no se completó completamente"
                        echo "Error: ${e.getMessage()}"
                    }
                }
            }
        }
        
        stage('Publish Report') {
            steps {
                echo '📊 Publicando reporte de seguridad...'
                script {
                    bat '''
                        echo === 📊 RESUMEN DEL ESCANEO DE SEGURIDAD === > reports\\summary.txt
                        echo Fecha: %date% %time% >> reports\\summary.txt
                        echo. >> reports\\summary.txt
                        
                        if exist reports\\zap_report.json (
                            echo ✅ Reporte encontrado >> reports\\summary.txt
                            echo. >> reports\\summary.txt
                            echo Contenido del reporte: >> reports\\summary.txt
                            type reports\\zap_report.json >> reports\\summary.txt
                        ) else (
                            echo ⚠️ No se encontró el reporte JSON >> reports\\summary.txt
                        )
                    '''
                }
                
                publishHTML([
                    reportDir: 'reports',
                    reportFiles: 'zap_report.html',
                    reportName: 'OWASP ZAP Security Report',
                    reportTitles: 'Reporte de Seguridad',
                    keepAll: true,
                    alwaysLinkToLastBuild: true
                ])
            }
        }
        
        stage('Analyze Results') {
            steps {
                echo '📝 Analizando resultados del escaneo...'
                script {
                    try {
                        // Leer el archivo JSON de manera segura
                        def jsonFile = readFile('reports/zap_report.json')
                        if (jsonFile) {
                            // Parsear JSON correctamente en Groovy
                            def json = readJSON text: jsonFile
                            
                            // Acceder a los alerts de manera segura
                            def alerts = []
                            if (json && json.site && json.site.size() > 0) {
                                alerts = json.site[0].alerts ?: []
                            }
                            
                            def highCount = 0
                            def mediumCount = 0
                            def lowCount = 0
                            def infoCount = 0
                            
                            alerts.each { alert ->
                                def risk = alert.riskdesc ?: ''
                                if (risk.startsWith('High')) highCount++
                                else if (risk.startsWith('Medium')) mediumCount++
                                else if (risk.startsWith('Low')) lowCount++
                                else if (risk.startsWith('Info')) infoCount++
                            }
                            
                            echo "📊 Vulnerabilidades encontradas:"
                            echo "  🔴 Alto: ${highCount}"
                            echo "  🟠 Medio: ${mediumCount}"
                            echo "  🟡 Bajo: ${lowCount}"
                            echo "  ℹ️ Info: ${infoCount}"
                            echo "  📈 Total: ${alerts.size()}"
                            
                            // Generar resumen JSON
                            def summary = [
                                high: highCount,
                                medium: mediumCount,
                                low: lowCount,
                                info: infoCount,
                                total: alerts.size(),
                                alerts: alerts
                            ]
                            
                            writeJSON file: 'reports/vulnerability_summary.json', json: summary
                            
                            // Generar informe en formato Markdown
                            def markdown = """
# 📊 Reporte de Seguridad - OWASP ZAP

**Fecha**: ${new Date()}
**Build**: #${env.BUILD_NUMBER}
**Aplicación**: CiberSeguri-ExamenTrasversal

## Resumen de Vulnerabilidades

| Severidad | Cantidad |
|-----------|----------|
| 🔴 Alto | ${highCount} |
| 🟠 Medio | ${mediumCount} |
| 🟡 Bajo | ${lowCount} |
| ℹ️ Info | ${infoCount} |
| **Total** | **${alerts.size()}** |

## Detalle de Vulnerabilidades

"""
                            alerts.each { alert ->
                                markdown += """
### ${alert.name ?: 'Sin nombre'}
- **Severidad**: ${alert.riskdesc ?: 'No especificada'}
- **URL**: ${alert.url ?: 'No especificada'}
- **Descripción**: ${alert.description ?: 'No especificada'}
- **Solución**: ${alert.solution ?: 'No especificada'}
---
"""
                            }
                            
                            writeFile file: 'reports/security_report.md', text: markdown
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error al analizar resultados: ${e.getMessage()}"
                        echo "⚠️ El archivo JSON puede no existir o estar corrupto"
                    }
                }
            }
        }
        
        stage('Send Summary Email') {
            steps {
                echo '📧 Resumen de resultados:'
                script {
                    // Mostrar resumen en consola
                    sh '''
                        echo "========================================="
                        echo "📊 RESUMEN DEL ESCANEO DE SEGURIDAD"
                        echo "========================================="
                        echo ""
                        if exist reports\\vulnerability_summary.json (
                            echo "✅ Reporte de vulnerabilidades generado"
                            echo "📁 Ubicación: reports/vulnerability_summary.json"
                            echo "📁 Reporte HTML: reports/zap_report.html"
                        ) else (
                            echo "⚠️ No se generó el reporte de vulnerabilidades"
                        )
                        echo ""
                        echo "========================================="
                    '''
                }
            }
        }
    }
    
    post {
        always {
            script {
                echo '📦 Archivando artefactos...'
                archiveArtifacts artifacts: 'reports/*', followSymlinks: false
                archiveArtifacts artifacts: '*.log', followSymlinks: false
            }
            echo '📦 Reportes archivados'
            
            bat '''
                echo Limpiando procesos de Flask...
                taskkill /F /IM python.exe /FI "WINDOWTITLE eq Flask*" 2>nul || echo No hay procesos de Flask
            '''
        }
        
        failure {
            echo '❌ El pipeline falló. Revisar los logs para más detalles.'
        }
        
        success {
            echo '✅ Pipeline completado exitosamente!'
            echo '📊 Reporte disponible en: ${BUILD_URL}/HTML_Report'
            echo '📊 Resumen disponible en: ${BUILD_URL}/artifact/reports/vulnerability_summary.json'
        }
        
        aborted {
            echo '⏹️ Pipeline cancelado'
        }
    }
}
