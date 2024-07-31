# Fibratus Kubernetes Testing
Designing a cloud-native response engine for Windows workloads in Kubernetes: <br/>
https://github.com/rabbitstack/fibratus

## The location of the local rules file:

```
cd "C:\\Program Files\Fibratus\Rules"
```

## My first test rule in Fibratus

I can simply download the rule from Github remotely using ```wget``` or ```curl```
```
wget https://raw.githubusercontent.com/nigel-falco/fibratus-k8s-testing/main/file_deletion.yml
```

```
- group: Detection of specific file deletion on Windows desktop
  description: |
    Detects when the file "helloworld.text" is deleted on a Windows desktop. This rule
    monitors for deletion events targeting this specific file, which may indicate
    unauthorized access or tampering.
  labels:
    tactic.id: TA0006
    tactic.name: Credential Access
    tactic.ref: https://attack.mitre.org/tactics/TA0006/
    technique.id: T1070
    technique.name: Indicator Removal on Host
    technique.ref: https://attack.mitre.org/techniques/T1070/
    subtechnique.id: T1070.004
    subtechnique.name: File Deletion
    subtechnique.ref: https://attack.mitre.org/techniques/T1070/004/
  rules:
    - name: Deletion of helloworld.text file
      condition: >
        delete_file
          and
        file.name = "helloworld.text"
      action: >
        {{
            emit . "File deletion detected: helloworld.text" ""
        }}
```
