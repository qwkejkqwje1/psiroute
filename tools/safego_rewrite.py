import re, sys, glob, os

def code_mask(s):
    n=len(s); m=bytearray(b'\x01'*n); i=0
    while i<n:
        c=s[i]
        if c=='/' and i+1<n and s[i+1]=='/':
            j=s.find('\n',i); j=n if j<0 else j
            for k in range(i,j): m[k]=0
            i=j
        elif c=='/' and i+1<n and s[i+1]=='*':
            j=s.find('*/',i+2); j=n if j<0 else j+2
            for k in range(i,j): m[k]=0
            i=j
        elif c=='"':
            j=i+1
            while j<n and s[j]!='"':
                j+= 2 if s[j]=='\\' else 1
            for k in range(i,min(j+1,n)): m[k]=0
            i=j+1
        elif c=='`':
            j=s.find('`',i+1); j=n-1 if j<0 else j
            for k in range(i,j+1): m[k]=0
            i=j+1
        elif c=="'":
            j=i+1
            while j<n and s[j]!="'":
                j+= 2 if s[j]=='\\' else 1
            for k in range(i,min(j+1,n)): m[k]=0
            i=j+1
        else: i+=1
    return m

def match(s,m,i,open_,close):
    assert s[i]==open_, (s[i-20:i+20])
    d=0
    for j in range(i,len(s)):
        if not m[j]: continue
        if s[j]==open_: d+=1
        elif s[j]==close:
            d-=1
            if d==0: return j
    raise ValueError("unbalanced")

LOOPS = {
 "a.serveProxy(ln, nil)":"a.ctx",
 "a.serveUI(uiLn)":"a.ctx",
 "a.serveProxy(ln, &proxyAuth":"a.ctx",
 "memTrimmer()":"context.Background()",
 "d.watch(ctx)":"ctx",
 "w.serve(ln)":"context.Background()",
}

def enclosing(s,pos):
    best=None
    for mm in re.finditer(r'(?m)^func (?:\((\w+) \*?(\w+)(?:\[.*?\])?\) )?(\w+)',s[:pos]):
        best=mm
    if not best: return "init"
    return (best.group(2)+"." if best.group(2) else "")+best.group(3)

def rewrite(path):
    s=open(path,encoding='utf-8').read()
    out=[]; last=0; counts={}; warns=[]; nrep=0
    m=code_mask(s)
    for mm in list(re.finditer(r'(?m)^([ \t]*)go ',s)):
        st=mm.start()+len(mm.group(1))
        if not m[st]: continue
        if st < last: continue  # nested in a span already rewritten; next pass
        body_start=mm.end()
        base=enclosing(s,st)
        if base not in counts:
            counts[base]=len(re.findall(r'safeGo\("'+re.escape(base)+r'(?:#\d+)?"',s))
        counts[base]+=1
        name=base if counts[base]==1 else f"{base}#{counts[base]}"
        if s.startswith('func(',body_start):
            p0=body_start+4
            p1=match(s,m,p0,'(',')')
            params=s[p0+1:p1]
            b0=s.index('{',p1)
            b1=match(s,m,b0,'{','}')
            a0=b1+1
            assert s[a0]=='(', (path,s[a0-30:a0+30])
            a1=match(s,m,a0,'(',')')
            args=s[a0+1:a1]
            inner=s[b0:b1+1]
            if not params.strip() and not args.strip():
                new=f'safeGo("{name}", func() {inner})'
            else:
                new=f'func({params}) {{ safeGo("{name}", func() {inner}) }}({args})'
            end=a1+1
        else:
            # call expression: find first '(' at depth 0 in code
            j=body_start
            while not (m[j] and s[j]=='('): j+=1
            c1=match(s,m,j,'(',')')
            expr=s[body_start:j]; args=s[j+1:c1]
            end=c1+1
            full=s[body_start:end]
            loopctx=None
            for k,v in LOOPS.items():
                if full.startswith(k): loopctx=v
            if loopctx:
                new=f'safeLoop({loopctx}, "{name}", func() {{ {full} }})'
            elif not args.strip():
                new=f'safeGo("{name}", {expr})'
            else:
                new=f'safeGo("{name}", func() {{ {full} }})'
                warns.append((path,s.count("\n",0,st)+1,full[:70].replace("\n"," ")))
        out.append(s[last:st]); out.append(new); last=end; nrep+=1
    out.append(s[last:])
    return ''.join(out), nrep, warns

if __name__=='__main__':
    tot=0
    for f in sorted(glob.glob('*.go')):
        if f.endswith('_test.go') or f=='safe.go': continue
        n_file=0
        while True:
            new,n,w=rewrite(f)
            if not n: break
            open(f,'w',encoding='utf-8').write(new); n_file+=n
            for x in w: print('   ARGS-CALL',x)
        if n_file: print(f,n_file); tot+=n_file
    print('total',tot)
