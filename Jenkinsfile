pipeline {
  parameters {         
        string(name: 'BranchName', defaultValue: 'master', description: 'Branch used by the job')  
    }
  agent {
    node {
      label 'Plugins'
    }

  }
  stages {
    stage('Build_Package_Extension') {
		steps {
			bat 'npm install -g tfx-cli'
			bat 'del *.vsix'
			bat 'C:\\Program Files\\nodejs\\node.exe C:\\Users\\tfs\\AppData\\Roaming\\npm\\node_modules\\tfx-cli\\_build\\tfx-cli.js extension create --manifest-globs vss-extension.json'
		}
	}
	stage('Build_Package_Extension') {
		steps {
			bat 'if exist C:\\Temp\\Temp_VSTS-Plugin rd /s /q C:\\Temp\\Temp_VSTS-Plugin'
			bat 'mkdir C:\\Temp\\Temp_VSTS-Plugin'
			bat 'copy *.vsix C:\\Temp\\Temp_VSTS-Plugin'
			bat 'rd /s /q .'
			bat 'copy C:\\Temp\\Temp_VSTS-Plugin\\*.vsix .'
			bat 'rd /s /q C:\\Temp\\Temp_VSTS-Plugin'
		}
    } 
	stage('Archive Artifacts') {
      steps {
        archiveArtifacts 'target/*.vsix'
      }
    }
  }
}
