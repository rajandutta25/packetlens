import gzip, base64
b64 = base64.b64encode(gzip.compress(open('samples/sample.pcap','rb').read(), 9)).decode()
t = open('tools/template.html').read().replace('__SAMPLE_B64__', b64)
open('index.html','w').write(t)
print(len(t))
