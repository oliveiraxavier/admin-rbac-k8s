# Kubernetes Admin RBAC

Painel local para criar e administrar identidades de acesso Kubernetes com permissões RBAC explícitas. O projeto não cria CRDs: usa `ServiceAccount`, `Role`, `RoleBinding` e a API `TokenRequest` nativas.

## Escopo atual

- O painel lista somente identidades criadas por ele, nos namespaces permitidos pelo backend. ServiceAccounts e tokens existentes, criados fora do painel, ainda não são inventariados.
- Uma identidade pode receber a mesma matriz de permissões em vários namespaces selecionados. As permissões são limitadas a `get`, `list` e `watch` para Pods, Services, Deployments, ReplicaSets, Jobs e CronJobs. A leitura de logs usa apenas `get` em `pods/log`. Secrets aceitam somente `get` sobre nomes explicitamente selecionados.
- O painel mostra e administra os bindings que ele próprio gerencia. Permissões adicionadas manualmente à mesma ServiceAccount fora do painel podem ampliar o acesso e não aparecem nesta matriz.
- Tokens têm validade solicitada entre 10 minutos e 365 dias. Se `ttlSeconds` for omitido na API, o backend usa 365 dias; isso não cria um token sem expiração. O API server pode aplicar uma duração menor. O valor é mostrado uma única vez; para obter outro, emita um novo token.
- Editar permissões atualiza a Role vinculada à ServiceAccount. A mudança afeta os tokens dessa identidade.
- A chave de administração da API é compartilhada e mantida apenas em memória pelo navegador. Este é um MVP para ambiente controlado, não um sistema de autenticação multiusuário.

## Onde os dados são salvos

- **No cluster Kubernetes (etcd):** a `ServiceAccount` fica no namespace de origem escolhido. Para cada namespace de acesso, o backend cria uma `Role` e uma `RoleBinding` namespaced que referencia essa ServiceAccount. Esses objetos persistem no cluster e podem ser inspecionados com `kubectl`.
- **Namespaces e permissões:** não há banco de dados próprio. O painel reconstrói os namespaces de acesso lendo os `RoleBindings` gerenciados; as regras ficam nas `Roles` correspondentes.
- **Token Kubernetes emitido:** a API `TokenRequest` devolve um JWT temporário, mas o backend não o grava em um `Secret` nem em banco. O frontend o mantém em memória para exibição única; fechar a janela/aba descarta a cópia do painel.
- **Segredo administrativo do painel:** vem da variável de ambiente `ADMIN_API_TOKEN` do processo Go e fica em memória no frontend enquanto conectado. Não é salvo no cluster nem em `localStorage`.

## Verbos e subrecursos

- `get` lê um objeto específico; `list` enumera objetos; `watch` acompanha mudanças em tempo real. O token pode ler os valores completos das Secrets nomeados; `list`, `watch`, nomes wildcard e nomes não informados são rejeitados.
- Logs são um subrecurso: o painel permite `get` em `pods/log`. Isso concede a ferramentas que usam o token a leitura dos logs no namespace escolhido; o painel ainda não tem uma tela própria de visualização de logs.
- `kubectl exec` acessa o subrecurso `pods/exec` e normalmente requer `create` nesse subrecurso (alguns clientes/transportes podem exigir `get`). Isso permite executar comandos dentro do container e não é equivalente a criar um Pod.
- A leitura ampla de Secrets e `pods/exec` continuam bloqueados pela allowlist do backend. Mesmo o `get` nominal de Secrets expõe valores sensíveis; use apenas para identidades específicas e namespaces necessários.

## Pré-requisitos

- Go 1.24 ou superior
- Node.js 26 (`nvm use` usa o `.nvmrc`)
- Acesso a um cluster Kubernetes por `KUBECONFIG` ou configuração in-cluster

O usuário Kubernetes do backend precisa operar ServiceAccounts e criar TokenRequests nos namespaces configurados, além de criar/ler/atualizar/excluir Roles e RoleBindings. Para RBAC dinâmico, o Kubernetes também pode exigir os verbos `escalate` em Roles e `bind` nos papéis referenciados. Esses privilégios são sensíveis: limite o backend a namespaces dedicados e revise cuidadosamente os usuários com acesso à chave administrativa.

## Executar localmente

Terminal 1, na raiz do projeto:

```sh
cp .env.example .env
# Defina ADMIN_API_TOKEN em .env usando a saída de: openssl rand -hex 32
set -a
. ./.env
set +a
cd backend
go run ./cmd/server
```

Informe o valor de `ADMIN_API_TOKEN` no campo Segredo da API do painel. O arquivo `.env` é local e não deve ser commitado.

Terminal 2:

```sh
cd frontend
nvm use
npm install
npm start
```

Abra http://localhost:4200. O servidor Angular encaminha `/api` para `127.0.0.1:8080` durante o desenvolvimento.

## Verificações

```sh
cd backend && go test ./...
cd ../frontend && npm run build
```

## Endpoints

- `GET /healthz`: verificação de saúde sem autenticação.
- `GET /api/v1/namespaces`: namespaces permitidos.
- `GET /api/v1/tokens`: identidades gerenciadas e permissões.
- `POST /api/v1/tokens`: cria ServiceAccount, Role e RoleBinding em cada namespace selecionado, e emite o token inicial.
- `PUT /api/v1/tokens/{namespace}/{name}`: substitui os namespaces de escopo e as permissões.
- `POST /api/v1/tokens/{namespace}/{name}/issue`: emite um novo token temporário.
- `DELETE /api/v1/tokens/{namespace}/{name}`: remove a identidade e os objetos RBAC associados.

Todos os endpoints `/api` exigem `Authorization: Bearer <ADMIN_API_TOKEN>`.

## Produção

Não exponha o backend diretamente à internet. O segredo estático compartilhado não substitui autenticação de usuários, autorização por função, auditoria ou TLS. Antes de uso compartilhado, integre um provedor de identidade, proteja a API por TLS, armazene segredos fora do frontend e revise o RBAC efetivo concedido à identidade do backend. A validação da aplicação não reduz o impacto de um backend comprometido.
