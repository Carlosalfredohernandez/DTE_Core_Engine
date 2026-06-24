import hashlib
from pathlib import Path
A=Path('tools/accepted_extracted.xml').read_bytes()
B=Path('tools/generated_extracted_from_builder.xml').read_bytes()
print('accepted size', len(A))
print('generated_extracted size', len(B))
print('accepted sha1', hashlib.sha1(A).hexdigest())
print('generated_extracted sha1', hashlib.sha1(B).hexdigest())
ml=min(len(A),len(B))
for i in range(ml):
    if A[i]!=B[i]:
        print('first_diff_offset', i)
        start=max(0,i-120)
        end=min(len(A),i+120)
        print('--- accepted context ---\n', A[start:end].decode('latin-1',errors='replace'))
        print('--- generated context ---\n', B[start:end].decode('latin-1',errors='replace'))
        break
else:
    if len(A)!=len(B):
        print('first_diff_offset', ml)
    else:
        print('files identical')
