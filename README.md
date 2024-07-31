# Fibratus Kubernetes Testing
Designing a cloud-native response engine for Windows workloads in Kubernetes: <br/>
https://github.com/rabbitstack/fibratus

## The location of the local rules file:
Seems to be some admin permission issues writing to this default directory
```
cd "C:\\Program Files\Fibratus\Rules"
```

Created a new file directory for test rules in Fibratus:
```
cd "C:\\Users\nigel\Fibratus_Rules"
```

Point the ```config``` file to take rules from an external URL - my ```Github repo```:
```
cd "C:\\Program Files\Fibratus\Config"
```

```
# =============================== Filters ===============================================

# Contains the definition of detection rules. Rules are contained within rule group files.
# Rule definitions can reside in the local file system or also can be served over HTTP/S.
# For local file system rule paths, it is possible to use the glob expression to load the
# rules from different directory locations.
filters:
  rules:
    #from-paths:
    #  - C:\Program Files\Fibratus\Rules\*.yml
    from-urls:
      - https://raw.githubusercontent.com/nigel-falco/fibratus-k8s-testing/main/file_deletion.yml
  #macros:
    #from-paths:
      #- C:\Program Files\Fibratus\Rules\Macros\*.yml
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


### Current Issue in Windows Event Logs

![fibratus-eventlogs](https://github.com/user-attachments/assets/6543ab52-340e-47fa-9db9-b58df1ecdadf)

