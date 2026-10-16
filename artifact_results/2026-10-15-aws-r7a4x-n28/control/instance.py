import json, urllib.request
base='http://169.254.169.254/latest/'
token=urllib.request.urlopen(urllib.request.Request(base+'api/token', method='PUT', headers={'X-aws-ec2-metadata-token-ttl-seconds':'60'}),timeout=5).read().decode()
result={name:urllib.request.urlopen(urllib.request.Request(base+'meta-data/'+name,headers={'X-aws-ec2-metadata-token':token}),timeout=5).read().decode() for name in ['instance-type','instance-life-cycle']}
print(json.dumps(result,indent=2))
assert result == {'instance-type':'r7a.4xlarge','instance-life-cycle':'on-demand'},result
