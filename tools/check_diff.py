from pathlib import Path
import hashlib
A=Path('accepted_extracted.xml').read_bytes()
B=Path('pipeline_run/generated_extracted_resigned_merged.xml').read_bytes()

def normalize(b):
    s = b.decode('latin-1')
    if s.lstrip().startswith('<?xml'):
        parts = s.split('?>',1)
        if len(parts)>1:
            s = parts[1]
    return s.lstrip().encode('latin-1')

An=normalize(A)
Bn=normalize(B)
print('accepted_norm size', len(An))
print('generated_norm size', len(Bn))
print('accepted_norm sha1', hashlib.sha1(An).hexdigest())
print('generated_norm sha1', hashlib.sha1(Bn).hexdigest())
ml=min(len(An),len(Bn))
for i in range(ml):
    if An[i]!=Bn[i]:
        print('first_diff_offset', i)
        start=max(0,i-120)
        end=min(len(An),i+120)
        print('--- accepted context ---\n', An[start:end].decode('latin-1',errors='replace'))
        print('--- generated context ---\n', Bn[start:end].decode('latin-1',errors='replace'))
        break
else:
    if len(An)!=len(Bn):
        print('first_diff_offset', ml)
    else:
        print('files identical')
