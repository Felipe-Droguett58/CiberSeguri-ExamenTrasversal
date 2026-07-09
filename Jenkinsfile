pipeline {
    agent any
    
    environment {
        DOCKER_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
        APP_PORT = '5000'
        // Usar Python 3.11 si está instalado, o el que tengas
        PYTHON_PATH = 'python'
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
                        pip install flask==2.2.3 bcrypt markupsafe
                    )
                    
                    echo ✅ Dependencias instaladas correctamente
                '''
            }
        }
        
        stage('Setup Database') {
            steps {
                echo '🗄️ Creando base de datos...'
                bat '''
                    echo Creando base de datos SQLite...
                    python create_db.py
                    
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
                        timeout /t 5 /nobreak >nul 2>&1 || echo Esperando...
                        
                        echo Verificando conexión...
                        set RETRIES=0
                        :check_app
                        curl -s -f http://localhost:%APP_PORT% >nul 2>&1
                        if %ERRORLEVEL% EQU 0 (
                            echo ✅ Aplicación iniciada correctamente en http://localhost:%APP_PORT%
                            goto :app_ready
                        )
                        set /a RETRIES=%RETRIES%+1
                        if %RETRIES% GEQ 30 (
                            echo ❌ No se pudo iniciar la aplicación después de 30 intentos
                            echo === LOGS DE LA APLICACIÓN ===
                            type app.log
                            exit /b 1
                        )
                        echo Intentando conectar... (%RETRIES%/30)
                        timeout /t 2 /nobreak >nul 2>&1
                        goto :check_app
                        
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
                                -t http://host.docker.internal:%APP_PORT% ^
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
                        def jsonFile = readFile('reports/zap_report.json')
                        if (jsonFile) {
                            def json = readJSON text: jsonFile
                            def alerts = json.site ? json.site[0].alerts ?: [] : []
                            
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
                            
                            // Generar resumen
                            def summary = [
                                high: highCount,
                                medium: mediumCount,
                                low: lowCount,
                                info: infoCount,
                                total: alerts.size(),
                                alerts: alerts
                            ]
                            
                            writeJSON file: 'reports/vulnerability_summary.json', json: summary
                        }
                    } catch (Exception e) {
                        echo "⚠️ Error al analizar resultados: ${e.getMessage()}"
                    }
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
        }
        
        aborted {
            echo '⏹️ Pipeline cancelado'
        }
    }
}
