# Privilege Escalation Cheat Sheets 🛡️

Este repositório contém anotações práticas e guias de referência rápida (Cheat Sheets) focados em técnicas de **Escalonamento de Privilégios** para ambientes Linux e Windows. 

As anotações foram consolidadas durante workshops e laboratórios práticos, servindo como um guia de consulta rápida para processos de enumeração, identificação de misconfigurations e exploração de vetores comuns.

---

## 📂 Conteúdo do Repositório

O conteúdo está dividido por sistema operacional para facilitar a navegação durante operações:

* **[Linux Privilege Escalation](./Linux/README.md):** Focado em vetores como SUID, Cron Jobs, Capabilities, arquivos de configuração expostos e enumeração de kernel.
* **[Windows Privilege Escalation](./Windows/README.md):** (Aguardando conteúdo) Focado em vetores como permissões de serviços, DLL Hijacking, Unquoted Service Paths e enumeração via PowerShell/CMD.

---

## 🚀 Como utilizar

Estes arquivos foram estruturados para serem consultados sequencialmente durante uma fase de pós-exploração:
1.  **Enumeração inicial:** Entender o contexto do sistema e do usuário.
2.  **Busca por "Low Hanging Fruits":** Arquivos esquecidos e permissões mal configuradas.
3.  **Exploração:** Comandos específicos para elevar o nível de acesso.

---

## ⚠️ Aviso Legal (Disclaimer)

O conteúdo deste repositório foi criado exclusivamente para fins educacionais e de estudo em segurança ofensiva. O uso dessas técnicas em sistemas sem autorização prévia é ilegal. O autor não se responsabiliza pelo uso indevido das informações aqui contidas.

---
