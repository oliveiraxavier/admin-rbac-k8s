# Instruções para agentes

## Estrutura

- `backend/`: API Go e módulo Go (`backend/go.mod`, `backend/go.sum`).
- `frontend/`: aplicação Angular; use a versão Node definida em `frontend/.nvmrc`.
- O backend acessa Kubernetes com `client-go`. Testes devem usar clientes fake, nunca um cluster real.

## Regras gerais

- Preserve alterações existentes do usuário e mantenha as mudanças restritas à tarefa.
- Não altere a diretiva `go` de `backend/go.mod` sem autorização explícita.
- Não aplique, exclua ou modifique recursos em um cluster real sem pedido explícito. Prefira testes locais/fakes.
- Trate tokens, kubeconfigs e variáveis secretas como credenciais: não os imprima, registre em logs, inclua em exemplos reais ou grave no frontend.
- Siga os padrões e a arquitetura existentes; o projeto usa recursos Kubernetes nativos, sem CRD.

## Setup and commands

### Backend Go

1 . Setup and commands

- Execute comandos Go a partir de `backend/`.
- Após mudanças no backend, rode `go test ./...`.
- Rode `go mod tidy` somente quando alterar dependências, também a partir de `backend/`.
- Não aumente nem reduza a versão de Go sem autorização.

### Frontend Angular

- Execute comandos Node a partir de `frontend/` e rode `nvm use` antes deles.
- Após mudanças no frontend, rode `npm run build`; use `npm test` quando alterar comportamento coberto por testes.
- Não mude a versão de Node definida em `.nvmrc` sem autorização.
- A versão do node está definida em `.nvmrc`. Sempre considere isso.

## Servidores e validação manual

- Inicie um servidor apenas quando a tarefa exigir validação manual ou o usuário pedir.
- Antes de iniciar, verifique portas em uso e escolha portas livres, diferentes das portas padrão da aplicação. Ajuste o proxy local apenas se necessário.
- Encerre os processos iniciados pelo agente ao terminar a validação; não deixe servidores em background.
