#!/usr/bin/env python3
"""Query public Maven coordinates only; never upload source or credentials."""
import argparse,json,re,urllib.request,datetime
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('tree');parser.add_argument('output');args=parser.parse_args()
coordinates=[]
for line in Path(args.tree).read_text().splitlines():
    match=re.search(r'([\w.-]+):([\w.-]+):jar:([^: ]+):(?:compile|runtime|test|provided)',line)
    if match: coordinates.append(match.groups())
queries=[{'package':{'ecosystem':'Maven','name':g+':'+a},'version':v} for g,a,v in coordinates]
try:
    request=urllib.request.Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries}).encode(),headers={'Content-Type':'application/json'})
    response=json.load(urllib.request.urlopen(request,timeout=25))
    findings=[{'coordinate':':'.join(c),'advisories':r.get('vulns',[])} for c,r in zip(coordinates,response['results']) if r.get('vulns')]
    result={'date':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'https://api.osv.dev/v1/querybatch','packages':len(coordinates),'findings':findings,'status':'completed; applicability requires official advisory review'}
except Exception as error:
    result={'packages':len(coordinates),'status':'BLOCKED','reason':type(error).__name__}
Path(args.output).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
