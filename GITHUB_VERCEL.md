# Subir no GitHub e publicar na Vercel

## 1. Criar o repositório no GitHub

1. Acesse github.com → **New repository**
2. Nome: `cyber-hunter-lab` (ou o que preferir)
3. Deixe **Private** se não quiser o código público
4. **Create repository**
5. Na tela seguinte, clique em **uploading an existing file**
6. Arraste os arquivos deste projeto

**ATENÇÃO — não suba o arquivo `.env`.** Ele tem sua chave da API. Ele já
está no `.gitignore`, mas se você arrastar arquivos manualmente o GitHub
não respeita o `.gitignore` — confira e remova o `.env` da lista antes de
confirmar o upload. A chave vai na Vercel, no passo 3.

Também não suba: `node_modules/`, `dist/`.

## 2. Conectar na Vercel

1. Acesse vercel.com → entre com a conta do GitHub
2. **Add New → Project**
3. Escolha o repositório que você acabou de criar
4. A Vercel detecta Vite sozinha. Confira:
   - **Framework Preset:** Vite
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`

## 3. Colocar a chave (importante)

Ainda na tela de criação do projeto, abra **Environment Variables** e
adicione:

- **Name:** `GEMINI_API_KEY`
- **Value:** sua chave (a que começa com `AIzaSy`)

Marque para todos os ambientes (Production, Preview, Development).

Depois clique em **Deploy**.

Assim a chave fica guardada na Vercel e **não precisa ir para o GitHub**.

## 4. Pronto

O site sobe em `seu-projeto.vercel.app`. O arquivo `vercel.json` já cuida
das rotas internas, então `/admin.login` não dá 404.

## Sobre o painel de admin na Vercel

A Vercel publica isto como site estático, igual ao Netlify. Então o painel
de admin continua mostrando a tela de "indisponível aqui" — e tudo bem: a
chave já vai embutida no build, então a IA funciona para todos os usuários
sem precisar do painel.

O mesmo vale para o "Coletar evidências" (scanner de URL), que precisa de
servidor.

Se um dia quiser essas funções, aí é hospedagem com Node rodando o
`server.js` (Render), não Vercel estática.

## Atualizar o site depois

Alterou algo? Só subir o arquivo alterado no GitHub — a Vercel republica
sozinha a cada mudança. Não precisa mexer em mais nada.
