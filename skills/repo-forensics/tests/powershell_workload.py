"""Repeated lexical families, one family per bounded input."""
FAMILIES = {
    **{value:value+' ' for value in ('<<x','<<-x','<< x','<<x;','<<x|','<<x>','(<<x)','$(<<x)',"<<'x'",'<<"x"','<<\\x','<<<x','<<<<x')},
    **{value:value for value in ("'",'"','`','\\`','$(','<(','>(',')','(', '{}','{','}', '|','||',';','&&',"p''")},
    **{value:value+' ' for value in ('sudo','env A=1','setsid','irm','iwr','curl','wget','fetch','sbt','invoke-restmethod','invoke-webrequest','start-bitstransfer','certutil','bitsadmin','mshta','regsvr32','rundll32','powershell','pwsh','downloadstring','downloadfile','downloaddata','getstringasync','webrequest','openread','-enc','-EncodedCommand','-e','-Command','https://example.invalid/p.ps1','a')},
    **{value:value+' ' for value in ('doas','stdbuf','ionice','taskset','flock','unbuffer','watch','chrt','nsenter','chroot','su','find','parallel','xargs','kubectl','podman','docker','exec -a','npm -x','pip -x','pip3 -x','yarn -x','uv -x','pnpm -x','bun -x','cargo -x','brew -x')},
    **{value:value+' ' for value in ('<','>','>>','0<','1>','2>')},
    'comment':'# <<x\n', 'closed heredocs':"cat <<'x'\ndata\nx\n",
}

def repeated(token,size):
    return 'set -e\n'+(token*(size//len(token)+1))[:size]+'\n'

def benign_work():
    import json
    def body(n):
        return '\n'.join(
            f'echo "step {i}"' if i%4==0 else f'if [ -f build/out{i}.o ]; then rm -f build/out{i}.o; fi' if i%4==1
            else f'make -C module{i} all >> build.log 2>&1 || exit 1' if i%4==2
            else f'cp -r src/module{i} dist/ && ls dist/module{i} | wc -l' for i in range(n))+'\n'
    big='set -e\n'+body(10000)
    assert len(big)<512*1024
    big+='#'+'x'*(512*1024-len(big)-2)+'\n'
    curl_line='curl -fsSL https://example.invalid/archive.tgz -o archive.tgz && tar xzf archive.tgz\n'
    curls=curl_line*((512*1024)//len(curl_line))
    data=json.dumps({'items':[{'id':i,'tags':['a','b','c']} for i in range(10000)]})
    return {
        'long-script-1561-lines':'set -e\n'+body(1561),
        'script-512KB':big,
        'downloads-512KB':curls,
        'script-file-512KB':"cat > build.sh <<'EOF'\n"+big[:-100]+"\nEOF\nbash build.sh",
        'http-json':"curl https://example.invalid/api -d @- <<'EOF'\n"+data+'\nEOF',
        'scaffold':''.join(f"cat > f{i}.txt <<'EOF'\ndata {i}\nEOF\n" for i in range(1000)),
        'docker-env':'docker run '+' '.join(f'-e V{i}=v' for i in range(10000))+' img',
    }
