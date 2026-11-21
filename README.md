# Kubernetes Admin RBAC

Painel local para criar e administrar identidades de acesso Kubernetes com permissões RBAC explícitas. O projeto não cria CRDs: usa `ServiceAccount`, `Role`, `RoleBinding` e a API `TokenRequest` nativas.

## Escopo atual

- O painel lista somente identidades criadas por ele, nos namespaces permitidos pelo backend. ServiceAccounts e tokens existentes, criados fora do painel, ainda não são inventariados.
- Uma identidade pode receber a mesma matriz de permissões em vários namespaces selecionados. As permissões são limitadas a `get`, `list` e `watch` para Pods, Services, Deployments, ReplicaSets, Jobs e CronJobs. A leitura de logs usa apenas `get` em `pods/log`. Secrets aceitam somente `get` sobre nomes explicitamente selecionados.
- O painel mostra e administra os bindings que ele próprio gerencia. Permissões adicionadas manualmente à mesma ServiceAccount fora do painel podem ampliar o acesso e não aparecem nesta matriz.
- Tokens têm validade solicitada entre 10 minutos e 365 dias. Se `ttlSeconds` for omitido na API, o backend usa 365 dias; isso não cria um token sem expiração. O API server pode aplicar uma duração menor. O valor é mostrado uma única vez; para obter outro, emita um novo token.
- Editar permissões atualiza a Role vinculada à ServiceAccount. A mudança afeta os tokens dessa identidade.
- O login principal pode usar Authentik via OpenID Connect. O backend valida a identidade e mantém uma sessão assinada em cookie `HttpOnly`; a chave compartilhada continua disponível somente como modo legado quando OIDC não está configurado.

## Onde os dados são salvos

- **No cluster Kubernetes (etcd):** a `ServiceAccount` fica no namespace de origem escolhido. Para cada namespace de acesso, o backend cria uma `Role` e uma `RoleBinding` namespaced que referencia essa ServiceAccount. Esses objetos persistem no cluster e podem ser inspecionados com `kubectl`.
- **Namespaces e permissões:** não há banco de dados próprio. O painel reconstrói os namespaces de acesso lendo os `RoleBindings` gerenciados; as regras ficam nas `Roles` correspondentes.
- **Token Kubernetes emitido:** a API `TokenRequest` devolve um JWT temporário, mas o backend não o grava em um `Secret` nem em banco. O frontend o mantém em memória para exibição única; fechar a janela/aba descarta a cópia do painel.
- **Sessão do painel:** no modo Authentik, o navegador recebe um cookie de sessão `HttpOnly`, assinado pelo backend e válido por até oito horas (ou até o vencimento do ID token). O segredo de assinatura fica apenas em `AUTHENTIK_SESSION_SECRET`; tokens de acesso do Authentik não são armazenados no navegador.
- **Modo legado:** `ADMIN_API_TOKEN` mantém a autenticação compartilhada anterior apenas quando as variáveis OIDC não estão configuradas.

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

## Login com Authentik

### Subir o Authentik

Com Docker e Docker Compose instalados, execute o script a partir da raiz do
repositório:

```sh
./authentik/start-authentik.sh
```

Na primeira execução, o script gera segredos fortes e grava-os em
`authentik/.env` (ignorado pelo Git). Ele também limita o serviço a
`127.0.0.1:9000`, acessível apenas na máquina local. **Execute o script somente
na primeira configuração:** ele substitui `authentik/.env`. Para iniciar
novamente uma instância já configurada, use:

```sh
cd authentik
docker compose up -d
```

Para parar os serviços sem apagar os dados, execute `docker compose stop` no
diretório `authentik`. Não remova o volume `database` se quiser preservar a
configuração e os dados do Authentik.

Na primeira configuração, abra
http://localhost:9000/if/flow/initial-setup/ e defina a senha da conta
administrativa inicial do Authentik.

### Configurar login OIDC

No Authentik, crie um grupo para os usuários que podem administrar o painel
(por exemplo, `k8s-admins`) e adicione somente os administradores a esse grupo.
Crie uma aplicação com provedor OAuth2/OpenID Connect:

- Use o fluxo Authorization Code.
- Cadastre `http://localhost:4200/auth/callback` como Redirect URI.
- Habilite os escopos `openid`, `profile` e `email`.
- Configure o provedor para incluir um claim `groups` no ID token, contendo os
  grupos do usuário.
- Restrinja a aplicação no Authentik para que somente o grupo `k8s-admins`
  tenha acesso.
- Copie o issuer URL, o client ID e o client secret do provedor.

Configure o backend com os dados do provedor. `AUTHENTIK_ALLOWED_GROUPS`
adiciona a verificação do grupo no próprio backend; o nome deve corresponder
exatamente ao valor presente no claim `groups`:

```sh
export AUTHENTIK_ISSUER_URL="http://localhost:9000/application/o/<slug-da-aplicacao>/"
export AUTHENTIK_CLIENT_ID="<client-id>"
export AUTHENTIK_CLIENT_SECRET="<client-secret>"
export AUTHENTIK_REDIRECT_URL="http://localhost:4200/auth/callback"
export AUTHENTIK_SESSION_SECRET="$(openssl rand -hex 32)"
export AUTHENTIK_ALLOWED_GROUPS="k8s-admins"
export TARGET_NAMESPACES="default,canary-deployment"
cd backend
go run ./cmd/server
```

Use o issuer URL exato apresentado pelo Authentik. Em produção, configure HTTPS para o issuer e para a aplicação; o backend exige HTTPS no redirect fora de `localhost`. Opcionalmente, `AUTHENTIK_ALLOWED_GROUPS` aceita uma lista separada por vírgulas. Para restringir grupos, inclua um claim `groups` no ID token do provedor. Quando OIDC está configurado, `ADMIN_API_TOKEN` não autentica requisições.

Use as duas restrições — acesso à aplicação no Authentik e
`AUTHENTIK_ALLOWED_GROUPS` no backend — para garantir que somente
administradores autorizados possam acessar o painel.

## Verificações

```sh
cd backend && go test ./...
cd ../frontend && npm run build
```

## Hook pre-commit

O script `.githooks/pre-commit` formata os arquivos Go do backend, executa `go test ./...` e `go vet ./...`, e então compila o frontend com a versão Node definida em `frontend/.nvmrc`. Ative-o em cada clone com:

```sh
git config core.hooksPath .githooks
```

Se a formatação alterar um arquivo Go staged, o hook interrompe o commit para que as mudanças sejam revisadas e staged explicitamente.

## Endpoints

- `GET /healthz`: verificação de saúde sem autenticação.
- `GET /auth/login`, `GET /auth/callback`, `GET /auth/logout`: fluxo OIDC de login e logout quando Authentik está configurado.
- `GET /auth/session`: informa o modo de autenticação e o estado da sessão para a interface.
- `GET /api/v1/namespaces`: namespaces permitidos.
- `GET /api/v1/tokens`: identidades gerenciadas e permissões.
- `POST /api/v1/tokens`: cria ServiceAccount, Role e RoleBinding em cada namespace selecionado, e emite o token inicial.
- `PUT /api/v1/tokens/{namespace}/{name}`: substitui os namespaces de escopo e as permissões.
- `POST /api/v1/tokens/{namespace}/{name}/issue`: emite um novo token temporário.
- `DELETE /api/v1/tokens/{namespace}/{name}`: remove a identidade e os objetos RBAC associados.

Os endpoints `/api` exigem uma sessão Authentik quando OIDC está configurado. No modo legado, exigem `Authorization: Bearer <ADMIN_API_TOKEN>`.

## Produção

Não exponha o backend diretamente à internet. Use TLS no proxy reverso, issuer e redirect OIDC; proteja `AUTHENTIK_SESSION_SECRET` e o client secret fora do frontend; considere configurar grupos permitidos e auditoria; e revise o RBAC efetivo concedido à identidade do backend. A validação da aplicação não reduz o impacto de um backend comprometido.
