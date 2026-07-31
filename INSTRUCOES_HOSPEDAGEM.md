# Como publicar (modo simples — buildar e pronto)

Site estático (Netlify, GitHub Pages, qualquer host de arquivos).
Uma chave só, embutida no site, servindo todos os usuários. Sem servidor.

## Passo a passo

1. Renomeie o arquivo `.env.example` para `.env`.
2. Abra o `.env` e cole sua chave do Gemini:

       GEMINI_API_KEY=sua_chave_aqui

3. Rode:

       npm install
       npm run build

4. Isso cria a pasta `dist/`. No Netlify, arraste **o conteúdo de dentro
   da pasta `dist/`** (o `index.html` + a pasta `assets/`). NÃO arraste a
   pasta do projeto inteira, nem a pasta `dist` por fora.

Pronto. O site abre, pede login do usuário, e a IA funciona pra todo mundo
usando a sua chave — sem ninguém precisar colar chave.

## Login do usuário

- usuário: `carollamas`
- senha: `@@@Fe321`

(dá pra trocar no código, em `src/components/LoginPage.tsx`.)

## Aviso honesto sobre a chave embutida

No modo estático a chave fica dentro do código do site (embora ofuscada).
Alguém muito determinado consegue extrair. Para o seu caso (uma chave sua
servindo o site) costuma ser aceitável — mas se quiser a chave 100%
escondida e um painel de admin funcionando, aí precisa de hospedagem com
servidor (ver abaixo).

## Painel de admin (/admin.login)

O painel de admin (bloquear IP, trocar chave pelo site, estatísticas) só
funciona em hospedagem COM SERVIDOR (Node), tipo Render. Em site estático
ele abre mas mostra um aviso e não opera — isso é esperado, não é bug.
Como a chave já vai embutida no build, você NÃO precisa do admin pra o
site funcionar.

Se um dia quiser o admin funcionando: suba num host Node (Render), com
Start Command `npm start` e a variável `ADMIN_TOKEN` definida.
