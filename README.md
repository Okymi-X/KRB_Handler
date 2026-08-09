<p align="center">
  <img src="caramelo.jpeg" alt="Caramelo Storm" width="160">
</p>

<h1 align="center">KRB_Handler</h1>

<p align="center">
  <strong>Configurador de ambiente Kerberos (KDC) para pentest de Active Directory.</strong><br>
  Aponta a sua Kali para o domínio alvo em <strong>um comando</strong> — sem editar
  <code>/etc/krb5.conf</code>, <code>/etc/hosts</code> e o relógio na mão toda vez que
  aparece um erro de KDC.
</p>

<p align="center">
  <em>Feito por <strong>Avocado</strong> · equipe <strong>Caramelo Storm</strong></em><br>
  <a href="https://www.linkedin.com/in/rafael-raugi/">💼 LinkedIn</a> ·
  <a href="https://www.youtube.com/@avocado-shell">📺 YouTube @avocado-shell</a>
</p>

---

Toda vez que você troca de domínio — HTB, OSCP, um lab GOAD, um cliente — usar Kerberos
(`-k`) vira a mesma novela: descobrir o realm, descobrir o FQDN do DC, escrever o
`[realms]` e o `[domain_realm]` no `/etc/krb5.conf`, botar o DC no `/etc/hosts` e ainda
acertar o relógio. Erra uma linha e a ferramenta cospe um erro de KDC que não diz o que
está errado.

O `KRB_Handler` faz **só isso**, e faz rápido:

```bash
sudo ./KRB_Handler.py set 10.10.11.42
```

Ele sonda o alvo, descobre tudo sozinho e escreve os três lugares por você.

> **O que ele NÃO é:** não ataca, não pede credencial, não pega TGT, não chama impacket
> nem nenhuma outra ferramenta. É só o encanamento — depois disso as **suas** ferramentas
> funcionam com `-k`. Python 3 puro, **zero dependências**.

## Os erros que ele mata

| O erro que aparece na sua cara | Causa real | O que o KRB_Handler faz |
|---|---|---|
| `Cannot find KDC for realm "CORP.LOCAL"` | realm sem bloco em `[realms]` | escreve o bloco com `kdc`, `admin_server` e `kpasswd_server` |
| `Clock skew too great` / `KRB_AP_ERR_SKEW` | relógio fora do DC | lê a hora **do próprio KDC** e sincroniza |
| `Server not found in Kerberos database` | usou IP, ou o nome não bate com o SPN | põe o FQDN no `/etc/hosts` e desliga `rdns` / canonicalização |
| `KDC reply did not match expectations` | `[domain_realm]` mandando o host pro realm errado (clássico em domínio filho) | mapeia cada host pelo **sufixo mais longo** |
| `Response too big for UDP, retrying with TCP` | PAC grande estoura o datagrama | `udp_preference_limit = 1` (força TCP) |
| `KDC has no support for encryption type` | domínio velho só com RC4 | `--weak` habilita RC4/DES |
| `Name or service not known` no FQDN do DC | sem DNS do domínio | entrada no `/etc/hosts` com FQDN + domínio + nome curto |

## Como ele descobre tudo sem credencial

Um único handshake **SMB2 na porta 445**, anônimo, entrega o pacote inteiro:

- o **NEGOTIATE** responde com o `SystemTime` do servidor → o relógio do KDC (o *skew*);
- o **SESSION_SETUP** com um `NTLMSSP NEGOTIATE` faz o servidor devolver um *CHALLENGE*
  cujos `AV_PAIRs` trazem **domínio DNS, FQDN do DC, NetBIOS e a floresta**.

Não autentica nada — para no *challenge*. Se a 445 estiver fechada, cai para **LDAP
rootDSE** anônimo (389), depois **NTP** (123) para o relógio e **DNS reverso** para o nome.
Se nada responder, você passa na mão com `--realm` / `--dc`.

## Uso

```bash
sudo ./KRB_Handler.py set 10.10.11.42        # detecta e aplica tudo (o comando principal)
sudo ./KRB_Handler.py add 192.168.56.11      # soma um domínio filho / trust ao mesmo perfil
sudo ./KRB_Handler.py use htb                # troca de ambiente num comando
     ./KRB_Handler.py list                   # perfis salvos (marca o ativo)
     ./KRB_Handler.py status                 # realm ativo, DCs, hosts e skew agora
     ./KRB_Handler.py check                  # diagnóstico: portas 88/445/389/464, DNS, skew
sudo ./KRB_Handler.py clock 10.10.11.42      # só o relógio
sudo ./KRB_Handler.py restore                # devolve krb5.conf, /etc/hosts e NTP ao original
```

Opções de `set` / `add`:

| Flag | Para quê |
|---|---|
| `--realm CORP.LOCAL` | força o realm (pula a detecção) |
| `--dc dc01.corp.local` | força o FQDN do DC |
| `--profile <nome>` | nomeia o perfil (padrão: o domínio detectado) |
| `--no-clock` / `--no-hosts` | não encosta no relógio / no `/etc/hosts` |
| `--faketime` | em vez de mexer no relógio, gera um wrapper `faketime` |
| `--weak` | habilita RC4/DES para labs e domínios antigos |

### Exemplo — lab de 3 domínios

```bash
sudo ./KRB_Handler.py set 192.168.56.10 --profile hogwarts   # floresta raiz
sudo ./KRB_Handler.py add 192.168.56.11                      # domínio filho
sudo ./KRB_Handler.py add 192.168.56.12                      # floresta com trust
```

Os três realms convivem no mesmo `krb5.conf`, cada host apontando para o **seu** KDC.
Amanhã você volta pro HTB com `use htb` e volta pro lab com `use hogwarts`.

## Perfis

Cada ambiente é um perfil em `~/.krb-profiles/profiles/<nome>.json`. Trocar de perfil
**reescreve** o `krb5.conf` e o bloco do `/etc/hosts` inteiros, então nunca sobra sujeira
de um alvo anterior — que é exatamente como um `krb5.conf` editado na mão vira um campo
minado de realms mortos.

## Segurança do seu ambiente

- **Backup automático** do `/etc/krb5.conf` e do `/etc/hosts` originais na primeira
  execução, em `~/.krb-profiles/backup/`. `restore` devolve tudo.
- **`/etc/hosts` cirúrgico** — só o bloco entre `# >>> KRB_Handler` e `# <<< KRB_Handler`
  é tocado; o resto do arquivo fica intacto.
- **Relógio** — antes de ajustar, desliga o NTP automático (senão ele desfaz o ajuste em
  segundos) e **registra** que desligou; `restore` religa. Se você não quiser mexer no
  relógio da máquina, `--faketime` gera um wrapper e o relógio real não muda.
- **Auto-eleva com `sudo`** só nos comandos que escrevem. `list`, `status`, `show` e
  `check` rodam como usuário comum.

## Requisitos

- Python 3 (**stdlib apenas** — sem dependências externas)
- `sudo` para os comandos que escrevem em `/etc`
- Opcional: `faketime` (só para o modo `--faketime`)

## Estrutura

```
KRB_Handler.py    a ferramenta (Python 3, stdlib, auto-sudo)
caramelo.jpeg     logo da equipe
~/.krb-profiles/                (criado em runtime; NÃO versionado)
  ├── active                    nome do perfil ativo
  ├── profiles/<nome>.json      realms, KDCs e hosts do ambiente
  ├── backup/                   krb5.conf.orig e hosts.orig
  └── state.json                o que foi alterado no sistema (p/ o restore)
```

## Aviso

Ferramenta de apoio a **operações ofensivas autorizadas**. Ela altera arquivos de sistema
(`/etc/krb5.conf`, `/etc/hosts`) e o relógio da máquina — use na sua VM de ataque, dentro
do escopo de uma **autorização por escrito**. Você é responsável pelo uso.

## Licença

[MIT](LICENSE) — uso autorizado apenas em assessments com autorização por escrito.

---

<p align="center">
  <sub>⚡ <strong>Caramelo Storm</strong> ·
  <a href="https://www.linkedin.com/in/rafael-raugi/">LinkedIn</a> ·
  <a href="https://www.youtube.com/@avocado-shell">YouTube @avocado-shell</a></sub>
</p>
