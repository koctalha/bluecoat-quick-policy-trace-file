# Blue Coat ProxySG Quick Policy Trace Tool (Symantec - Broadcom)

## Description
CLI tool for activating and downloading policy trace faster. 

## Installation
```bash
pip install -r requirements.txt
```

## Usage
1. Execute python script.
```bash
python3 bluecoat_quick_policy_trace.py --pincode 1234 -proxy 172.16.22.21 -client 192.168.10.61 -username admin -password 'testPW' -enablePassword 'testePW' 
```
2. Credentials are going be stored encrypted with pincode under 'db.csv'. Script can be executable without credential parameters.
```bash
python3 bluecoat_quick_policy_trace.py -pin 1234 -p 172.16.22.21 -c 192.168.10.61 
```
3. During the first initialization, program will delete old trace files on ProxySG, and deploy policy trace command.

4. During the second initialization, program will delete policy trace command from the ProxySG, and download the generated trace file.

## Known Issues

1.  Sometimes, policy installation stops after the "inline policy local end-of-file" command. No negative impact has observed. After stopping program with "ctrl+c", program should be reinitialized.  
