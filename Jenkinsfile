pipeline {
  agent { label "windows-1" }
  
  stages {
    stage('Build ws_mail with cmake') {
      steps {
        bat 'mkdir cibuild'
        bat 'cd cibuild && cmake -DBoost_LIBRARY_DIR=C:/SDKs/boost_1_76_0/lib -DBoost_INCLUDE_DIR=C:/SDKs/boost_1_76_0 .. -G "Unix Makefiles"'
        bat 'cd cibuild && make'
      }
    }
  }
  
  post {
        always {
            archiveArtifacts artifacts: 'cibuild/wsmail.exe', fingerprint: true
        }
  }
}
