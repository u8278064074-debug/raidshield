╔══════════════════════════════════════════════════════════════╗
║   RAID SHIELD — HÉBERGEMENT GRATUIT SANS CARTE BANCAIRE      ║
╚══════════════════════════════════════════════════════════════╝

DEUX OPTIONS :
  ➤ OPTION A : GLITCH  (le plus simple, 0 effort)
  ➤ OPTION B : RENDER  (plus fiable, un peu plus de réglages)

⚠️  Dans les deux cas, tu dois aussi activer les intents privilégiés
    sur https://discord.com/developers/applications/1548789432205971616/bot
    (SERVER MEMBERS INTENT + MESSAGE CONTENT INTENT → Save)
    pour que le bot ait la protection COMPLÈTE.

═══════════════════════════════════════════════════════════════
OPTION A — GLITCH (le plus simple, recommandé)
═══════════════════════════════════════════════════════════════
1. Va sur https://glitch.com → « Sign in » → « Sign up » avec ton email
   (ou continue avec Google/Apple — AUCUNE carte demandée)
2. Clique sur ton avatar (en bas à gauche) → « New project »
   → « glitch-hello-node » (un projet vide Node)
3. Dans l'onglet « Files » (à gauche), il y a des fichiers par défaut.
   SUPPRIME tout ce qui est inutile (server.js, public/, etc.)
   → SURTOUT supprime « server.js » si présent.
4. Clique sur le bouton « ⬆️ Upload » (en haut de la liste des fichiers)
   et téléverse le fichier :  raidshield-cloud.zip
   → Glitch le décompresse tout seul dans le projet.
5. Ouvre le fichier « .env » créé dans le projet, et écris :
      TOKEN=MON_TOKEN_DISCORD
   (remplace MON_TOKEN_DISCORD par le token réel de ton bot)
6. Le projet se relance tout seul. Vérifie le bouton « Logs » (en bas)
   : tu dois voir « Connecté en tant que Easy Tuning#5403 ».
7. KEEPALIVE : pour éviter les coupures de ton bot, crée un compte
   GRATUIT sur https://uptimerobot.com → « Add New Monitor » →
   type « HTTPS » → URL = l'URL de ton projet Glitch
   (copie-la dans le panneau de droite de Glitch, clique Project →
   « Share » → URL publique) → interval 5 minutes → Create.
   Le bot restera ainsi éveillé la plupart du temps.

═══════════════════════════════════════════════════════════════
OPTION B — RENDER (plus fiable, 15 min de veille)
═══════════════════════════════════════════════════════════════
1. Crée un compte gratuit sur https://render.com (email, AUCUNE carte)
2. Rendement : Render a besoin d'un dépôt GitHub pour déployer.
   - Crée un compte GitHub gratuit (https://github.com → Sign up, sans carte)
   - Sur GitHub : bouton vert « New » → crée un dépôt privé « raidshield »
   - Onglet « Add file » → « Upload files » → téléverse :
       raidshield.js, package.json, package-lock.json
     puis « Commit changes »
3. Sur Render : « New » → « Web Service » → connecte GitHub →
   choisis ton dépôt « raidshield »
4. Config :
   - Environment : Node
   - Build Command :   npm install
   - Start Command :   node raidshield.js
   - (Gratuit : instance « Free »)
5. Onglet « Environment » (en bas) → « Add Environment Variable » :
      KEY = TOKEN   VALUE = ton token Discord réel
6. « Deploy Web Service » → attends 2-3 min → le statut passe « Live »
7. Clique sur l'URL « https://xxx.onrender.com » → tu dois voir
   « RaidShield OK » → c'est que le bot tourne.
8. KEEPALIVE : même principe (UptimeRobot, monitor HTTPS toutes les
   5 min sur l'URL ci-dessus) pour éviter les mises en veille.

═══════════════════════════════════════════════════════════════
COMMANDES / VÉRIFIE SUR DISCORD
═══════════════════════════════════════════════════════════════
Une fois le bot en ligne, tape  /raid status  dans ton serveur.
Si tu veux vérifier les logs du bot (Glitch) : onglet « Logs ».
Un bot à la fois, surtout : si le bot local tourne encore sur ton
PC, arrête-le avant (sinon deux bots en même temps).
  Sur ton PC :  Get-Process node | Stop-Process   (ou ferme la fenêtre)