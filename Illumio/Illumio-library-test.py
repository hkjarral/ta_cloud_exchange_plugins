from illumio import *
import illumio
import json

pce = PolicyComputeEngine('https://poc1.illum.io', port='443', org_id='65865')
pce.set_credentials('api_18b1781ffa42d0779', 'a4df05297bf1f2e022dfed63bd17ab814eaab7eb568631f2aa169bd8ee4f6ce0')
#workloads = pce.workloads.get(
#    params={
#        'managed': True
#    }
#)

print(pce.check_connection())
# label_ref = illumio.Reference(href='/orgs/65865/labels/281474976754944')
labels = pce.labels.get(params={"value":"quarantine"})

#for label in labels:
print(labels)

refs = [label.href for label in labels]
#print(json.dumps([refs]))
workloads = pce.workloads.get(params={'labels': json.dumps([refs])})
#print(workloads)

for workload in workloads:
    for interface in workload.interfaces:
        print(interface.address)

