pipeline {
    agent {
        docker {
            image 'python:3.11-slim'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }
    
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
                sh '''
                    echo "Verificando Python..."
                    python --version
                    
                    echo "Instalando dependencias..."
                    pip install -r requirements.txt
                    
                    echo "✅ Dependencias instaladas correctamente"
                '''
            }
        }
        
        stage('Setup Database') {
            steps {
                echo '🗄️ Creando base de datos...'
                sh '''
                    python create_db.py
                    echo "✅ Base de datos creada"
                '''
            }
        }
        
        stage('Start Application') {
            steps {
                echo '🚀 Iniciando aplicación Flask...'
                script {
                    sh '''
                        # Matar procesos previos
                        pkill -f "vulnerable_flask_app.py" || true
                        
                        # Iniciar la app en background
                        nohup python vulnerable_flask_app.py > app.log 2>&1 &
                        
                        # Esperar que la app esté lista
                        echo "⏳ Esperando que la aplicación inicie..."
                        for i in {1..30}; do
                            if curl -s -f http://localhost:${APP_PORT} > /dev/null 2>&1; then
                                echo "✅ Aplicación iniciada correctamente"
                                break
                            fi
                            echo "⏳ Intentando conectar... ($i/30)"
                            sleep 2
                        done
                        
                        # Verificar conexión
                        if curl -s -f http://localhost:${APP_PORT} > /dev/null 2>&1; then
                            echo "✅ Aplicación corriendo en http://localhost:${APP_PORT}"
                        else
                            echo "❌ No se pudo iniciar la aplicación"
                            cat app.log
                            exit 1
                        fi
                    '''
                }
            }
        }
        
        stage('Run OWASP ZAP Scan') {
            steps {
                echo '🔍 Ejecutando escaneo de seguridad con OWASP ZAP...'
                script {
                    try {
                        sh '''
                            mkdir -p reports
                            
                            docker run \
                                -v $(pwd):/zap/wrk/:rw \
                                ${DOCKER_IMAGE} \
                                zap-baseline.py \
                                -t http://localhost:${APP_PORT} \
                                -r zap_report.html \
                                -J zap_report.json \
                                -z "-config api.disablekey=true" \
                                || echo "⚠️ ZAP terminó con advertencias"
                            
                            if [ -f zap_report.html ]; then
                                cp zap_report.html reports/
                                echo "✅ Reporte HTML generado"
                            fi
                            
                            if [ -f zap_report.json ]; then
                                cp zap_report.json reports/
                                echo "✅ Reporte JSON generado"
                            fi
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
                    sh '''
                        echo "=== 📊 RESUMEN DEL ESCANEO DE SEGURIDAD ===" > reports/summary.txt
                        echo "Fecha: $(date)" >> reports/summary.txt
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
                archiveArtifacts artifacts: 'reports/*', followSymlinks: false
                archiveArtifacts artifacts: '*.log', followSymlinks: false
            }
            echo '📦 Reportes archivados'
            
            sh '''
                echo "Limpiando procesos..."
                pkill -f "vulnerable_flask_app.py" || true
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
