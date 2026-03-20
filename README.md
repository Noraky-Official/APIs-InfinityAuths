<div align="center">
  <h1>🛡️ InfinityAuth SDKs - V3 (Elite Edition)</h1>
  <p><strong>Autor & Criador: Noraky</strong></p>
  <p>Proteção Nível Militar, AES-256-CBC com IV Dinâmico, Anti-Dumping & Anti-TypeCrash.</p>
</div>

---

## 🎯 O que é o InfinityAuth?

O **InfinityAuth** é um ecossistema de autenticação de altíssima segurança projetado do zero por **Noraky**. Diferente de soluções open-source genéricas, a versão 3 (V3) implementa **End-to-End Encryption (E2EE)** nativa com pacotes de tráfego mutáveis. Isso significa que o Payload entre a sua Aplicação Cliente e o nosso Servidor NodeJS nunca será o mesmo duas vezes.

## 🚀 Principais Inovações (V3)

- **Criptografia Dinâmica (AES-256-CBC):** Geração randômica de Vetor de Inicialização (IV) a cada milissegundo de trânsito de pacotes (Imune a Replay Attacks).
- **Hardware ID (HWID) Nativo:** Tranca as sessões literalmente na placa-mãe do usuário via WMI/WinAPI, impedindo o compartilhamento ilícito de contas de forma impenetrável.
- **Fail-Safe Timeout:** Arquitetura à prova de Crash. Evita que a interface (UI) da sua aplicação congele ou trave em decorrência de eventuais picos de rede/servidor.
- **Cross-App Protection:** O Motor Backend garante repúdio absoluto de anomalias, blindando as instâncias contra escalonamento de privilégios.

---

## 💻 Linguagens Disponíveis (SDKs)

### 1. C# (.NET)
Perfeitamente otimizado para Loaders de alto nível, Interfaces Windows Forms, WPF e Injetores.

**Como Usar:**
1. Adicione a classe `InfinityAuth.cs` ao seu projeto.
2. Instale o pacote Nuget `Newtonsoft.Json`.
3. Inicialize a API com as suas credenciais no seu script principal:

```csharp
using InfinityAuth;

// name, ownerid, secret, version
public static InfinityAuth api = new InfinityAuth(
    "NomeDoSeuApp", 
    "SeuOwnerID", 
    "SuaSecretV3", 
    "1.0"
);

// No evento Load (Inicialização):
api.Init();

// Exemplo de Login Assíncrono/Síncrono:
var resp = api.Login("usuario", "senha");
if (resp.success) {
    Console.WriteLine("Login efetuado! Bem-vindo " + resp.info.username);
}
```

### 2. C++ (Nativo / WinCrypt)
Desenvolvido cirurgicamente para máxima performance, Game Hacking e binários ultraleves. Ele dispensa bibliotecas pesadas de terceiros (como OpenSSL) pois injeta diretamente as requests de AES nas raízes criptográficas do Windows (`advapi32.lib` / CryptoAPI).

**Requisitos:** Adicione os arquivos `api.cpp`, `api.hpp`, `auth.hpp` à sua source. A SDK utiliza Curl e `nlohmann_json`.

**Como Usar:**
1. Abra e configure o arquivo `auth.hpp` com suas credenciais:
```cpp
// auth.hpp
static std::string name = "SuaApp"; 
static std::string ownerid = "SeuOwnerID";
static std::string secret = "SeuSecret"; 
static std::string version = "1.0";
```
2. Invoque os comandos a partir de qualquer ponto da sua Thread:
```cpp
#include "auth.hpp"

int main() {
    auth.init();
    
    auto res = auth.login("usuario", "senha");
    if (res.success) {
        printf("Logado com sucesso, %s!\n", res.info.username.c_str());
    }
}
```

### 3. Python
Excelente para ferramentas backend diretas, scripts de automação ou robôs que exigem verificação de HWID em Windows.

**Requisitos:** 
```bash
pip install pycryptodome requests
```

**Como Usar:**
```python
from InfinityAuth import InfinityAuth

api = InfinityAuth("MeuApp", "OwnerId", "Secret", "1.0")
api.init()

resp = api.login("usuario", "senha")
if resp.get("success"):
    print("Sucesso! Operação Autorizada.")
```

---

## 📦 Webhooks e Variáveis Restritas (V3)
Além de licenças e logins convencionais, as SDKs agora suportam nativamente a recuperação de strings hiper-restritas diretamente do banco de dados na nuvem (útil para links ocultos de download ou bytes de arquivos) com segurança máxima.

* **C#:** `api.GetVar("link_download")` | `api.TriggerWebhook("login_log")`
* **C++:** `auth.get_var("link_download")` | `auth.trigger_webhook("login_log")`
* **Python:** `api.var("link_download")` | `api.webhook("login_log")`

---
> *© Copyright Noraky - Documentação e Engenharia.*
