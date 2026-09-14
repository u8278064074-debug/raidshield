/**
 * ─────────────────────────────────────────────────────────────
 *  ⚔️ RAID SHIELD — Bot anti-raid premium pour Discord
 *  Protection complète : anti-nuke, anti-spam, anti-massjoin,
 *  protection des rôles, journalisation, mode RAID & lockdown.
 * ─────────────────────────────────────────────────────────────
 */

import "dotenv/config";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Client,
  GatewayIntentBits,
  Partials,
  Events,
  AuditLogEvent,
  PermissionsBitField,
  EmbedBuilder,
  SlashCommandBuilder,
  ChannelType,
  ActivityType,
} from "discord.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = path.join(__dirname, "raidshield-config.json");

const WELCOME_CHANNEL_ID = "1548883819254517780"; // salon de bienvenue
const CITIZEN_ROLE_ID = "1548792320260972564"; // rôle 👥 Citoyen (auto-attribué aux nouveaux)
const REVIEW_CHANNEL_ID = "1548887315865149460"; // ⭐-avis (les /avis y sont postés)
const avisCooldowns = new Map(); // userId -> timestamp du dernier /avis

/* ------------------------------------------------------------------ */
/*  Configuration par défaut (chaque serveur peut la modifier)         */
/* ------------------------------------------------------------------ */

const DEFAULT_CONFIG = {
  enabled: true,
  logChannel: null, // ID du salon de logs
  quarantineRole: null, // rôle de quarantaine (optionnel)
  lockdown: false,
  lockdownUntil: null,
  raidMode: false,
  raidModeUntil: null,
  thresholds: {
    channelCreate: 4, // créations de salons en 10s → raid
    channelDelete: 4, // suppressions de salons en 10s → raid
    roleCreate: 3, // créations de rôles en 10s → raid
    roleDelete: 3, // suppressions de rôles en 10s → raid
    ban: 3, // bans en 10s → raid
    kick: 4, // kicks en 10s → raid
    spam: 5, // messages en 5s → avertissement anti-spam
    duplicate: 3, // messages identiques en 5s → anti-dup
    joinRush: 6, // arrivées en 10s → raid join
    botAdd: 2, // bots ajoutés en 30s → raid bots
    newAccountDays: 3, // comptes plus jeunes que ça = suspect
    actionWindow: 10_000, // fenêtre de détection (ms)
  },
  punishments: {
    default: "timeout", // timeout | kick | ban
    timeoutMinutes: 60,
    nuke: "ban", // punition pour destruction de salons/rôles/bans massifs
  },
  spam: {
    invites: true, // bloquer les invitations Discord dans les messages
    everyone: true, // bloquer @everyone / @here
    maxMentions: 4, // mentions autorisées par message (non-everyone)
  },
  whitelistUsers: [], // jamais punis
  whitelistRoles: [], // membres avec ce rôle = jamais punis
  protectedRoles: [], // rôles protégés : toute modification non staff = rollback
};

/* ------------------------------------------------------------------ */
/*  État en mémoire                                                    */
/* ------------------------------------------------------------------ */

const states = new Map(); // guildId -> { windows, spam, lockdownTimers }

function stateOf(guildId) {
  if (!states.has(guildId)) {
    states.set(guildId, {
      windows: {
        channelCreate: [],
        channelDelete: [],
        roleCreate: [],
        roleDelete: [],
        ban: [],
        kick: [],
        join: [],
        botAdd: [],
      },
      spam: new Map(), // userId -> { times: [], dupes: Map(hash->count), strikes: 0 }
    });
  }
  return states.get(guildId);
}

/* ------------------------------------------------------------------ */
/*  Configuration (persistée dans raidshield-config.json)              */
/* ------------------------------------------------------------------ */

const guildConfigs = new Map();

function loadConfigs() {
  try {
    const data = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
    for (const [k, v] of Object.entries(data)) guildConfigs.set(k, v);
  } catch {
    /* pas encore de config */
  }
}

function saveConfigs() {
  const data = Object.fromEntries(guildConfigs.entries());
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(data, null, 2), "utf8");
}

function configOf(guildId) {
  if (!guildConfigs.has(guildId)) {
    const cfg = structuredClone(DEFAULT_CONFIG);
    guildConfigs.set(guildId, cfg);
    saveConfigs();
  }
  return guildConfigs.get(guildId);
}

/* ------------------------------------------------------------------ */
/*  Utilitaires                                                        */
/* ------------------------------------------------------------------ */

const now = () => Date.now();
const prune = (arr, windowMs) => {
  const t = now();
  while (arr.length && t - arr[0] > windowMs) arr.shift();
  return arr;
};
const FLAGGED = [
  PermissionsBitField.Flags.Administrator,
  PermissionsBitField.Flags.ManageGuild,
  PermissionsBitField.Flags.ManageRoles,
  PermissionsBitField.Flags.ManageChannels,
  PermissionsBitField.Flags.BanMembers,
  PermissionsBitField.Flags.KickMembers,
  PermissionsBitField.Flags.ManageWebhooks,
  PermissionsBitField.Flags.MentionEveryone,
];
const hasDangerousPerms = (permString) =>
  FLAGGED.some((f) => (BigInt(permString) & BigInt(f)) !== 0n);

function isStaff(member) {
  if (!member) return false;
  if (member.roles?.cache) {
    const dangerous = member.roles.cache.find((r) => hasDangerousPerms(r.permissions.bitfield));
    if (dangerous) return true;
  }
  return member.permissions?.has(PermissionsBitField.Flags.Administrator) === true ||
    member.permissions?.has(PermissionsBitField.Flags.ManageGuild) === true;
}

function isWhitelisted(member, config) {
  if (!member) return false;
  if (config.whitelistUsers.includes(member.id)) return true;
  if (member.roles?.cache?.some((r) => config.whitelistRoles.includes(r.id))) return true;
  if (member.id === client.user?.id) return true;
  return false;
}

async function getAuditExecutor(guild, type, withinMs = 12_000) {
  try {
    const audit = await guild.fetchAuditLogs({ type, limit: 6 });
    const entry = audit.entries.find((e) => now() - e.createdTimestamp < withinMs) ?? audit.entries.first();
    return entry?.executor ?? null;
  } catch {
    return null;
  }
}

const CAN_PUNISH_NAMES = {
  ban: async (m) => (m.bannable ? m.ban({ reason: "RaidShield — raid détecté | " + (m._reason || "") }).catch(() => null) : null),
  kick: async (m) => (m.kickable ? m.kick("RaidShield — raid détecté | " + (m._reason || "")).catch(() => null) : null),
  timeout: (m) => (m.moderatable ? m.timeout((m._minutes || 60) * 60_000, "RaidShield — raid détecté | " + (m._reason || "")).catch(() => null) : null),
};

async function punish(member, level, reason, minutes = 60) {
  if (!member || !member.id) return false;
  const config = configOf(member.guild.id);
  if (isStaff(member) || isWhitelisted(member, config)) {
    await punishLog(member.guild, `⚠️ Tentative non punie`, `${member.user.tag} (${member.id}) — ${reason} (staff / whitelisté)`);
    return false;
  }
  member._reason = reason;
  member._minutes = minutes;
  const fn = CAN_PUNISH_NAMES[level] || CAN_PUNISH_NAMES.timeout;
  await fn(member);
  await punishLog(member.guild, level.toUpperCase(), `${member.user?.tag || member.id} — ${reason}`, level === "ban" ? 0xdb2a2a : level === "kick" ? 0xe8590c : 0xf2c053);
  return true;
}

/* ------------------------------------------------------------------ */
/*  Journalisation                                                     */
/* ------------------------------------------------------------------ */

async function resolveLogChannel(guild) {
  const config = configOf(guild.id);
  if (config.logChannel) {
    const c = await guild.channels.fetch(config.logChannel).catch(() => null);
    if (c) return c;
  }
  const fallback = guild.channels.cache.find(
    (c) => c.type === ChannelType.GuildText && /logs?|journal|mod/.test(c.name)
  );
  if (fallback) config.logChannel = fallback.id;
  return fallback ?? null;
}

async function log(guild, title, description, color = 0x5865f2) {
  try {
    const channel = await resolveLogChannel(guild);
    if (!channel) return;
    const embed = new EmbedBuilder()
      .setTitle(title)
      .setDescription(description)
      .setColor(color)
      .setTimestamp();
    await channel.send({ embeds: [embed] });
  } catch { /* salon indisponible */ }
}

const punishLog = log;

function logAlert(guild, summary, details, color = 0xdb2a2a) {
  return log(guild, summary, details, color);
}

/* ------------------------------------------------------------------ */
/*  Mode RAID & Lockdown                                               */
/* ------------------------------------------------------------------ */

function enableRaidMode(guild, reason, minutes = 30) {
  const config = configOf(guild.id);
  config.raidMode = true;
  config.raidModeUntil = now() + minutes * 60_000;
  config.lockdown = true;
  config.lockdownUntil = config.raidModeUntil;
  saveConfigs();
  return logAlert(
    guild,
    "🚨 MODE RAID ACTIVÉ",
    `**${reason}**\nLe serveur est en état d'alerte pendant **${minutes} min** :\n• Tout nouveau membre sera mis en timeout immédiatement\n• Toute création/suppression de salon et de rôle sera annulée\n• Toute punition est appliquée automatiquement\nUtilise **/raid unlock** manuellement si nécessaire.`,
    0xdb2a2a
  );
}

function disableRaidMode(guild) {
  const config = configOf(guild.id);
  config.raidMode = false;
  config.raidModeUntil = null;
  config.lockdown = false;
  config.lockdownUntil = null;
  saveConfigs();
  return log(guild, "✅ SÉCURITÉ RÉTABLIE", "Le mode raid est désactivé. Les mesures automatiques sont levées.", 0x2ecc71);
}

function setLockdown(guild, minutes = 60, enable = true) {
  const config = configOf(guild.id);
  if (enable) {
    config.lockdown = true;
    config.lockdownUntil = now() + minutes * 60_000;
  } else {
    config.lockdown = false;
    config.lockdownUntil = null;
  }
  saveConfigs();
  return log(
    guild,
    enable ? "🔒 LOCKDOWN ACTIVÉ" : "🔓 LOCKDOWN DÉSACTIVÉ",
    enable
      ? `Tout nouveau membre sera mis en timeout pendant **${minutes} min** jusqu'à <t:${Math.floor(config.lockdownUntil / 1000)}:R>.`
      : "Les nouveaux membres peuvent rejoindre normalement.",
    enable ? 0xe67e22 : 0x2ecc71
  );
}

/* ------------------------------------------------------------------ */
/*  Protections                                                        */
/* ------------------------------------------------------------------ */

async function onChannelCreate(channel) {
  if (!channel.guild) return;
  const guild = channel.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);
  prune(st.windows.channelCreate, config.thresholds.actionWindow);
  st.windows.channelCreate.push(now());

  const count = st.windows.channelCreate.length;
  if (!config.raidMode && count < config.thresholds.channelCreate) return;

  const executor = await getAuditExecutor(guild, AuditLogEvent.ChannelCreate);
  if (isStaff(executor) && !config.raidMode) return;

  // Rollback : supprime les salons créés en rafale
  let rolledBack = 0;
  for (const c of guild.channels.cache.filter((ch) => ch.id !== channel.id && now() - ch.createdTimestamp < 30_000)) {
    if (rolledBack >= 10) break;
    if (c.deletable) {
      await c.delete("RaidShield — suppression salons créés pendant le raid").catch(() => null);
      rolledBack++;
    }
  }
  if (channel.deletable) {
    await channel.delete("RaidShield — salon créé pendant un raid").catch(() => null);
    rolledBack++;
  }

  await logAlert(
    guild,
    "🚧 SALONS CRÉÉS EN MASSE",
    `**${count} salons** créés en ${config.thresholds.actionWindow / 1000}s → **${rolledBack} annulé(s)**, fautif : ${executor ?? "inconnu"} (<@${channel.id}>)`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `Création en masse de salons (${count} en ${config.thresholds.actionWindow / 1000}s)`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Création en masse de salons");
}

async function onChannelDelete(channel) {
  if (!channel.guild) return;
  const guild = channel.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);
  prune(st.windows.channelDelete, config.thresholds.actionWindow);
  st.windows.channelDelete.push(now());

  const count = st.windows.channelDelete.length;
  const executor = await getAuditExecutor(guild, AuditLogEvent.ChannelDelete);
  if (isStaff(executor) && !config.raidMode) return;

  const isNuke = config.raidMode || count >= config.thresholds.channelDelete;
  if (!isNuke) return;

  // Rollback : recrée le canal supprimé
  try {
    await guild.channels.create({
      name: channel.name,
      type: channel.type === ChannelType.GuildVoice || channel.type === ChannelType.GuildStageVoice
        ? channel.type
        : ChannelType.GuildText,
      parent: channel.parentId ?? undefined,
      reason: "RaidShield — restauration du salon supprimé",
    });
  } catch { /* permis manquants */ }

  await logAlert(
    guild,
    "💥 SALONS SUPPRIMÉS EN MASSE",
    `**${count} suppressions** détectées → salon restauré, fautif : ${executor ?? "inconnu"}`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `Suppressions en masse de salons (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Suppression en masse de salons");
}

async function onRoleCreate(role) {
  if (!role.guild) return;
  const guild = role.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);
  prune(st.windows.roleCreate, config.thresholds.actionWindow);
  st.windows.roleCreate.push(now());

  const count = st.windows.roleCreate.length;
  const executor = await getAuditExecutor(guild, AuditLogEvent.RoleCreate);
  if (isStaff(executor) && !config.raidMode) return;

  const isNuke = config.raidMode || count >= config.thresholds.roleCreate;
  if (!isNuke) return;

  if (role.editable) {
    await role.delete("RaidShield — rôle créé pendant un raid").catch(() => null);
  }

  await logAlert(
    guild,
    "🎭 RÔLES CRÉÉS EN MASSE",
    `**${count} rôles** créés → supprimés, fautif : ${executor ?? "inconnu"}`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `Création en masse de rôles (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Création en masse de rôles");
}

async function onRoleDelete(role) {
  if (!role.guild) return;
  const guild = role.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);
  prune(st.windows.roleDelete, config.thresholds.actionWindow);
  st.windows.roleDelete.push(now());

  const count = st.windows.roleDelete.length;
  const executor = await getAuditExecutor(guild, AuditLogEvent.RoleDelete);
  if (isStaff(executor) && !config.raidMode) return;

  const isNuke = config.raidMode || count >= config.thresholds.roleDelete;
  if (!isNuke) return;

  const snapshot = {
    name: role.name,
    color: role.color,
    hoist: role.hoist,
    mentionable: role.mentionable,
    permissions: role.permissions.bitfield,
    position: role.position,
  };
  try {
    await guild.roles.create({
      name: snapshot.name,
      color: snapshot.color,
      hoist: snapshot.hoist,
      mentionable: snapshot.mentionable,
      permissions: snapshot.permissions,
      reason: "RaidShield — restauration du rôle supprimé",
    });
  } catch { /* permis manquants */ }

  await logAlert(
    guild,
    "💥 RÔLES SUPPRIMÉS EN MASSE",
    `**${count} suppressions** détectées → rôle **${role.name}** restauré, fautif : ${executor ?? "inconnu"}`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `Suppressions en masse de rôles (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Suppression en masse de rôles");
}

function roleNeedsProtection(role, config) {
  return (
    config.protectedRoles.includes(role.id) ||
    hasDangerousPerms(role.permissions.bitfield)
  );
}

async function onRoleUpdate(oldRole, newRole) {
  if (!newRole.guild) return;
  const guild = newRole.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;

  const executor = await getAuditExecutor(guild, AuditLogEvent.RoleUpdate);
  if (executor?.id === client.user?.id) return; // le bot agit lui-même
  if (isStaff(executor)) return;

  const permChanged = oldRole.permissions.bitfield !== newRole.permissions.bitfield;
  const roleIsProtected = roleNeedsProtection(newRole, config);

  if (permChanged && roleIsProtected) {
    // Rollback des permissions
    await newRole.setPermissions(oldRole.permissions.bitfield, "RaidShield — restauration des permissions").catch(() => null);
    await logAlert(
      guild,
      "🛡️ PERMISSIONS MODIFIÉES",
      `Le rôle **${newRole.name}** a reçu des permissions sensibles → **annulé**, fautif : ${executor ?? "inconnu"}`,
      0xdb2a2a
    );
    if (executor) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Modification des permissions d'un rôle sensible");
  }
}

async function onBanAdd(ban) {
  const guild = ban.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);
  prune(st.windows.ban, config.thresholds.actionWindow);
  st.windows.ban.push(now());

  const count = st.windows.ban.length;
  const executor = await getAuditExecutor(guild, AuditLogEvent.MemberBanAdd);
  if (isStaff(executor) && !config.raidMode) return;

  const isNuke = config.raidMode || count >= config.thresholds.ban;
  if (!isNuke) return;

  // Unban des victimes
  try {
    await guild.members.unban(ban.user.id, "RaidShield — ban de masse annulé").catch(() => null);
  } catch { /* pas le droit de unban */ }

  await logAlert(
    guild,
    "⛔ BANS EN MASSE",
    `**${count} bans** détectés → annulés et membres restaurés, fautif : ${executor ?? "inconnu"}`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `Bans en masse (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Bans en masse");
}

async function onKickDetected(member) {
  const guild = member.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);
  prune(st.windows.kick, config.thresholds.actionWindow);
  st.windows.kick.push(now());

  const executor = await getAuditExecutor(guild, AuditLogEvent.MemberKick);
  if (isStaff(executor) && !config.raidMode) return;

  const count = st.windows.kick.length;
  const isNuke = config.raidMode || count >= config.thresholds.kick;
  if (!isNuke) return;

  await logAlert(
    guild,
    "👢 KICKS EN MASSE",
    `**${count} kicks** détectés → alerte, fautif : ${executor ?? "inconnu"}`,
    0xe8590c
  );
  if (!config.raidMode) await enableRaidMode(guild, `Kicks en masse (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Kicks en masse");
}

async function greetNewMember(member) {
  const guild = member.guild;
  const config = configOf(guild.id);
  if (!config.enabled || config.lockdown || config.raidMode) return;

  // Auto-attribution du rôle Citoyen
  try {
    const role = guild.roles.cache.get(CITIZEN_ROLE_ID);
    if (role && !member.roles.cache.has(role.id)) {
      await member.roles.add(role.id, "RaidShield — rôle Citoyen de bienvenue");
    }
  } catch { /* permissions insuffisantes */ }

  // Message de bienvenue
  try {
    const channel = guild.channels.cache.get(WELCOME_CHANNEL_ID);
    if (!channel || !channel.isTextBased()) return;
    const embed = new EmbedBuilder()
      .setTitle("🎉 Bienvenue sur EASY TUNING !")
      .setDescription(
        `Bienvenue **${member.user.username}** sur le serveur ! 🚗💨\n\n` +
        `Rôle **👥 Citoyen** attribué automatiquement.` +
        `\nPasse nous dire bonjour, explore les salons et bon jeu à toi !`
      )
      .setColor(0x2ecc71)
      .setThumbnail(member.user.displayAvatarURL({ size: 512 }))
      .setFooter({ text: "EASY TUNING" })
      .setTimestamp();
    await channel.send({ content: `${member}`, embeds: [embed] });
  } catch { /* salon indisponible */ }
}

async function onMemberAdd(member) {
  const guild = member.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const st = stateOf(guild.id);

  if (member.user.bot) {
    prune(st.windows.botAdd, 30_000);
    st.windows.botAdd.push(now());
    const count = st.windows.botAdd.length;
    if (config.raidMode || count >= config.thresholds.botAdd) {
      const executor = await getAuditExecutor(guild, AuditLogEvent.BotAdd, 30_000);
      await logAlert(
        guild,
        "🤖 BOTS AJOUTÉS",
        `**${count} bots** ajoutés en 30s → bots retirés, fautif : ${executor ?? "inconnu"}`,
        0xdb2a2a
      );
      if (member.kickable) await member.kick("RaidShield — ajout en masse de bots");
      if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Ajout en masse de bots");
      if (!config.raidMode) await enableRaidMode(guild, `Ajout en masse de bots (${count})`);
    }
    return;
  }

  prune(st.windows.join, config.thresholds.actionWindow);
  st.windows.join.push(now());
  const joinCount = st.windows.join.length;

  // Lockdown / raid mode → timeout immédiat du nouvel arrivant
  if (config.lockdown || config.raidMode) {
    const minutes = config.punishments.timeoutMinutes;
    await member.timeout(minutes * 60_000, "RaidShield — lockdown actif").catch(() => null);
    await log(guild, "🔒 NOUVEL ARRIVANT VERROUILLÉ", `${member.user.tag} rejoint pendant le lockdown → timeout ${minutes} min`, 0xe67e22);
    return;
  }

  // Rafle de comptes jeunes
  if (joinCount >= config.thresholds.joinRush && config.thresholds.joinRush > 0) {
    const accountAge = (now() - member.user.createdTimestamp) / 86_400_000;
    if (accountAge < config.thresholds.newAccountDays) {
      await member.timeout(config.punishments.timeoutMinutes * 60_000, "RaidShield — rafle de nouveaux comptes").catch(() => null);
      await logAlert(
        guild,
        "🚨 RAFLE DE NOUVEAUX COMPTES",
        `**${joinCount} membres** en ${config.thresholds.actionWindow / 1000}s, compte âgé de **${Math.floor(accountAge)}j** → timeout.`,
        0xdb2a2a
      );
    }
    if (!config.raidMode) await enableRaidMode(guild, `Rafle de nouveaux membres (${joinCount})`);
  }

  await greetNewMember(member);
}

async function onMemberUpdate(oldMember, newMember) {
  const guild = newMember.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;

  const added = newMember.roles.cache.filter((r) => !oldMember.roles.cache.has(r.id));
  if (added.size === 0) return;

  const executor = await getAuditExecutor(guild, AuditLogEvent.MemberRoleUpdate);
  if (executor?.id === client.user?.id) return;
  if (isStaff(executor)) return;

  for (const role of added.values()) {
    if (roleNeedsProtection(role, config)) {
      await newMember.roles.remove(role.id, "RaidShield — attribution d'un rôle sensible annulée").catch(() => null);
      await logAlert(
        guild,
        "🛡️ RÔLE SENSIBLE ATTRIBUÉ",
        `**${role.name}** retiré de ${newMember.user.tag}, fautif : ${executor ?? "inconnu"}`,
        0xdb2a2a
      );
      if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.default, "Attribution d'un rôle sensible");
    }
  }
}

/* ---------------------------- ANTI-SPAM ---------------------------- */

function spamState(guildId, userId) {
  const st = stateOf(guildId);
  if (!st.spam.has(userId)) {
    st.spam.set(userId, { times: [], dupes: new Map(), strikes: 0 });
  }
  return st.spam.get(userId);
}

async function spamPunish(member, config, reason) {
  const s = spamState(member.guild.id, member.id);
  s.strikes = (s.strikes || 0) + 1;
  if (s.strikes >= 3) {
    await punish(member, "kick", `Anti-spam (3e infraction) — ${reason}`);
  } else if (s.strikes >= 2) {
    await punish(member, "timeout", `Anti-spam (2e infraction) — ${reason}`, 60);
  } else {
    await punish(member, "timeout", `Anti-spam — ${reason}`, 10);
  }
}

async function onMessage(message) {
  if (message.author?.bot) return;
  if (!message.guild) return;
  const guild = message.guild;
  const config = configOf(guild.id);
  if (!config.enabled) return;
  const member = message.member;

  // Anti @everyone / @here
  if (config.spam.everyone && (message.content.includes("@everyone") || message.content.includes("@here"))) {
    await message.delete().catch(() => null);
    await log(guild, "🚫 @EVERYONE BLOQUÉ", `${member?.user.tag} a tenté d'utiliser @everyone/@here`, 0xe8590c);
    await spamPunish(member, config, "@everyone/@here");
    return;
  }

  // Anti invitations Discord
  if (config.spam.invites && /(discord\.(gg|io|me|li)\/\S+|discord(app)?\.com\/invite\/\S+)/i.test(message.content)) {
    await message.delete().catch(() => null);
    await log(guild, "🚫 INVITATION BLOQUÉE", `${member?.user.tag} a posté une invitation Discord`, 0xe8590c);
    await spamPunish(member, config, "invitation Discord");
    return;
  }

  // Anti mentions excessives
  let mentionCount = 0;
  if (message.mentions.everyone) mentionCount += 10;
  mentionCount += message.mentions.users.size + message.mentions.roles.size;
  if (mentionCount > config.spam.maxMentions) {
    await message.delete().catch(() => null);
    await spamPunish(member, config, "trop de mentions");
    return;
  }

  // Fenêtre anti-spam / anti-doublon
  const s = spamState(guild.id, message.author.id);
  prune(s.times, 5_000);
  s.times.push(now());

  const hash = message.content.toLowerCase().replace(/\s+/g, " ").trim();
  if (hash.length > 1) {
    s.dupes.set(hash, (s.dupes.get(hash) || 0) + 1);
  }
  for (const [h, c] of s.dupes) {
    if (c < config.thresholds.duplicate) continue;
    // purge des doublons
    const before = message.channel.messages.cache
      .filter((m) => m.author.id === message.author.id && m.content.toLowerCase().replace(/\s+/g, " ").trim() === h)
      .first(20);
    for (const m of before) {
      if (m.deletable) await m.delete().catch(() => null);
    }
    s.dupes.set(h, 0);
    await spamPunish(member, config, "messages en double");
    return;
  }

  if (s.times.length >= config.thresholds.spam) {
    s.times.length = 0;
    await message.delete().catch(() => null);
    await spamPunish(member, config, "spam de messages");
  }
}

/* ------------------------------------------------------------------ */
/*  Commandes slash                                                    */
/* ------------------------------------------------------------------ */

const badge = (guild) => {
  const config = configOf(guild.id);
  return {
    raid: config.raidMode,
    lockdown: config.lockdown,
    raidUntil: config.raidModeUntil,
    lockdownUntil: config.lockdownUntil,
    config,
  };
};

const PERM_REF = "Les administrateurs, les whitelistés et RaidShield lui-même ne sont jamais punis.";

const commands = [
  new SlashCommandBuilder()
    .setName("raid")
    .setDescription("Centre de contrôle anti-raid (statut, lockdown, config)")
    .addSubcommand((s) => s.setName("status").setDescription("État actuel de la protection"))
    .addSubcommand((s) =>
      s.setName("lockdown").setDescription("Verrouille le serveur : les nouveaux arrivants sont mis en timeout")
        .addIntegerOption((o) => o.setName("minutes").setDescription("Durée en minutes (défaut 60)").setMinValue(1).setMaxValue(1440)))
    .addSubcommand((s) => s.setName("unlock").setDescription("Lève le lockdown et le mode raid"))
    .addSubcommand((s) =>
      s.setName("config").setDescription("Ajuste un seuil de protection")
        .addStringOption((o) =>
          o.setName("cle").setDescription("Clé de configuration").setRequired(true)
            .addChoices(
              { name: "Seuil : salons créés (10s)", value: "channelCreate" },
              { name: "Seuil : salons supprimés (10s)", value: "channelDelete" },
              { name: "Seuil : rôles créés (10s)", value: "roleCreate" },
              { name: "Seuil : rôles supprimés (10s)", value: "roleDelete" },
              { name: "Seuil : bans (10s)", value: "ban" },
              { name: "Seuil : kicks (10s)", value: "kick" },
              { name: "Anti-spam : messages / 5s", value: "spam" },
              { name: "Anti-spam : doublons / 5s", value: "duplicate" },
              { name: "Seuil : rafle de connexions (10s)", value: "joinRush" },
              { name: "Suspect : âge du compte (jours)", value: "newAccountDays" },
              { name: "Seuil : bots ajoutés (30s)", value: "botAdd" },
              { name: "Fenêtre de détection (ms)", value: "actionWindow" },
              { name: "Punition par défaut (timeout/kick/ban)", value: "punishDefault" },
              { name: "Durée du timeout (minutes)", value: "timeoutMinutes" },
              { name: "Punition anti-nuke (timeout/kick/ban)", value: "nukePunish" },
            ))
        .addStringOption((o) => o.setName("valeur").setDescription("Nouvelle valeur").setRequired(true)))
    .addSubcommand((s) =>
      s.setName("punish").setDescription("Punition par défaut pour un spammeur")
        .addStringOption((o) =>
          o.setName("mode").setDescription("timeout, kick ou ban").setRequired(true)
            .addChoices(
              { name: "timeout (recommandé)", value: "timeout" },
              { name: "kick", value: "kick" },
              { name: "ban", value: "ban" }))),
  new SlashCommandBuilder()
    .setName("whitelist")
    .setDescription("Gère la liste des membres/rôles jamais punis par RaidShield")
    .addSubcommand((s) => s.setName("add").setDescription("Ajoute un membre à la whitelist").addUserOption((o) => o.setName("user").setDescription("Membre").setRequired(true)))
    .addSubcommand((s) => s.setName("remove").setDescription("Retire un membre de la whitelist").addUserOption((o) => o.setName("user").setDescription("Membre").setRequired(true)))
    .addSubcommand((s) => s.setName("list").setDescription("Liste les membres whitelistés"))
    .addSubcommand((s) => s.setName("role").setDescription("Ajoute un rôle à la whitelist").addRoleOption((o) => o.setName("role").setDescription("Rôle").setRequired(true)))
    .addSubcommand((s) => s.setName("roledel").setDescription("Retire un rôle de la whitelist").addRoleOption((o) => o.setName("role").setDescription("Rôle").setRequired(true))),
  new SlashCommandBuilder()
    .setName("protected")
    .setDescription("Rôles protégés : toute modif non-staff sera annulée")
    .addSubcommand((s) => s.setName("add").setDescription("Protège un rôle").addRoleOption((o) => o.setName("role").setDescription("Rôle").setRequired(true)))
    .addSubcommand((s) => s.setName("remove").setDescription("Retire la protection d'un rôle").addRoleOption((o) => o.setName("role").setDescription("Rôle").setRequired(true)))
    .addSubcommand((s) => s.setName("list").setDescription("Liste les rôles protégés")),
  new SlashCommandBuilder()
    .setName("logs")
    .setDescription("Configure le salon de journalisation")
    .addSubcommand((s) => s.setName("set").setDescription("Salon où sont envoyés les logs").addChannelOption((o) => o.setName("salon").setDescription("Salon de logs").setRequired(true)))
    .addSubcommand((s) => s.setName("unset").setDescription("Supprime le salon de logs configuré")),
  new SlashCommandBuilder()
    .setName("qrole")
    .setDescription("Définit le rôle de quarantaine appliqué pendant un raid")
    .addStringOption((o) => o.setName("role").setDescription("ID du rôle, ou 'aucun'").setRequired(true)),
  new SlashCommandBuilder()
    .setName("avis")
    .setDescription("Laisse un avis sur le serveur (note de 1 à 5 étoiles)")
    .addIntegerOption((o) => o.setName("note").setDescription("Note de 1 à 5 étoiles").setRequired(true).setMinValue(1).setMaxValue(5))
    .addStringOption((o) => o.setName("message").setDescription("Ton message (facultatif)").setMaxLength(300)),
];

async function handleInteraction(interaction) {
  if (!interaction.isChatInputCommand()) return;
  const guild = interaction.guild;
  const config = configOf(guild.id);

  const requireAdmin = async () => {
    const member = interaction.member;
    const ok = member.permissions.has(PermissionsBitField.Flags.ManageGuild) || isWhitelisted(member, config);
    if (!ok) {
      await interaction.reply({ content: "❌ Tu as besoin de la permission **Gérer le serveur** pour cette commande.", ephemeral: true });
      return false;
    }
    return true;
  };

  const reply = (content, ephemeral = true) => interaction.reply({ content, ephemeral });

  if (interaction.commandName === "raid") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();

    if (sub === "status") {
      const th = config.thresholds;
      const parts = [
        `🛡️ **État** : ${config.enabled ? "actif" : "désactivé"}`,
        `🚨 **Mode RAID** : ${config.raidMode ? "ACTIF jusqu'à <t:" + Math.floor(config.raidModeUntil / 1000) + ":T>" : "inactif"}`,
        `🔒 **Lockdown** : ${config.lockdown ? "ACTIF jusqu'à <t:" + Math.floor(config.lockdownUntil / 1000) + ":T>" : "inactif"}`,
        ``,
        `📊 **Seuils (fenêtre ${(th.actionWindow / 1000).toFixed(0)}s)** :`,
        `     Salons créés  → ${th.channelCreate}`,
        `     Salons suppr. → ${th.channelDelete}`,
        `     Rôles créés   → ${th.roleCreate}`,
        `     Rôles suppr.  → ${th.roleDelete}`,
        `     Bans  → ${th.ban}   Kicks → ${th.kick}`,
        `     Connexions → ${th.joinRush}   Bots ajoutés → ${th.botAdd}`,
        `     Anti-spam  → ${th.spam} msg / 5s   Doublons → ${th.duplicate}`,
        `     Compte suspect → < ${th.newAccountDays} jours`,
        ``,
        `⚖️ **Punitions** : défaut = \`${config.punishments.default}\`, nuke = \`${config.punishments.nuke}\`, timeout = ${config.punishments.timeoutMinutes} min`,
        `🛡️ **Whitelist** : ${config.whitelistUsers.length} membres, ${config.whitelistRoles.length} rôles`,
        `🔐 **Rôles protégés** : ${config.protectedRoles.length}`,
        `📢 **Salon de logs** : ${config.logChannel ? `<#${config.logChannel}>` : "automatique"}`,
      ];
      return reply(parts.join("\n"));
    }

    if (sub === "lockdown") {
      const minutes = interaction.options.getInteger("minutes") ?? 60;
      await setLockdown(guild, minutes, true);
      return reply(`🔒 Lockdown démarré pour ${minutes} min. Les nouveaux arrivants seront mis en timeout automatiquement.`);
    }

    if (sub === "unlock") {
      disableRaidMode(guild);
      return reply("🔓 Protection désactivée. L'accès est de nouveau normal.");
    }

    if (sub === "config") {
      const key = interaction.options.getString("cle");
      const raw = interaction.options.getString("valeur").trim();
      if (key === "punishDefault" || key === "nukePunish") {
        if (!["timeout", "kick", "ban"].includes(raw)) return reply("❌ Valeur invalide (timeout, kick, ban).");
        config.punishments[key === "punishDefault" ? "default" : "nuke"] = raw;
      } else if (key === "timeoutMinutes") {
        config.punishments.timeoutMinutes = Math.max(1, Math.min(1440, parseInt(raw) || 60));
      } else {
        const n = parseInt(raw);
        if (Number.isNaN(n) || n < 0) return reply("❌ Valeur numérique invalide.");
        config.thresholds[key] = n;
      }
      saveConfigs();
      return reply(`✅ \`${key}\` mis à jour → **${raw}**`);
    }

    if (sub === "punish") {
      const mode = interaction.options.getString("mode");
      config.punishments.default = mode;
      saveConfigs();
      return reply(`✅ Punition par défaut → **${mode}**`);
    }
  }

  if (interaction.commandName === "whitelist") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();
    if (sub === "add") {
      const u = interaction.options.getUser("user");
      if (!config.whitelistUsers.includes(u.id)) config.whitelistUsers.push(u.id);
      saveConfigs();
      return reply(`✅ ${u.tag} ajouté à la whitelist.`);
    }
    if (sub === "remove") {
      const u = interaction.options.getUser("user");
      config.whitelistUsers = config.whitelistUsers.filter((id) => id !== u.id);
      saveConfigs();
      return reply(`✅ ${u.tag} retiré de la whitelist.`);
    }
    if (sub === "list") {
      const names = config.whitelistUsers.map((id) => `<@${id}>`).join(", ") || "Aucun";
      const roles = config.whitelistRoles.map((id) => `<@&${id}>`).join(", ") || "Aucun";
      return reply(`🛡️ **Membres** : ${names}\n🛡️ **Rôles** : ${roles}`);
    }
    if (sub === "role") {
      const r = interaction.options.getRole("role");
      if (!config.whitelistRoles.includes(r.id)) config.whitelistRoles.push(r.id);
      saveConfigs();
      return reply(`✅ Rôle <@&${r.id}> whitelisté.`);
    }
    if (sub === "roledel") {
      const r = interaction.options.getRole("role");
      config.whitelistRoles = config.whitelistRoles.filter((id) => id !== r.id);
      saveConfigs();
      return reply(`✅ Rôle <@&${r.id}> retiré de la whitelist.`);
    }
  }

  if (interaction.commandName === "protected") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();
    if (sub === "add") {
      const r = interaction.options.getRole("role");
      if (!config.protectedRoles.includes(r.id)) config.protectedRoles.push(r.id);
      saveConfigs();
      return reply(`🔐 Rôle <@&${r.id}> protégé : toute modif non-staff sera annulée.`);
    }
    if (sub === "remove") {
      const r = interaction.options.getRole("role");
      config.protectedRoles = config.protectedRoles.filter((id) => id !== r.id);
      saveConfigs();
      return reply(`🔓 Rôle <@&${r.id}> n'est plus protégé.`);
    }
    if (sub === "list") {
      const roles = config.protectedRoles.map((id) => `<@&${id}>`).join(", ") || "Aucun";
      return reply(`🔐 **Rôles protégés** : ${roles}`);
    }
  }

  if (interaction.commandName === "logs") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();
    if (sub === "set") {
      const ch = interaction.options.getChannel("salon");
      config.logChannel = ch.id;
      saveConfigs();
      return reply(`📢 Logs → <#${ch.id}>`);
    }
    if (sub === "unset") {
      config.logChannel = null;
      saveConfigs();
      return reply("📢 Salon de logs défini sur **automatique** (recherche d'un salon 'logs').");
    }
  }

  if (interaction.commandName === "qrole") {
    if (!(await requireAdmin())) return;
    const raw = interaction.options.getString("role");
    if (/^(aucun|none|null)$/i.test(raw)) {
      config.quarantineRole = null;
      saveConfigs();
      return reply("✅ Rôle de quarantaine désactivé.");
    }
    const role = await guild.roles.fetch(raw).catch(() => null);
    if (!role) return reply("❌ Rôle introuvable. Donne l'**ID** du rôle (Paramètres du rôle → clic droit).");
    config.quarantineRole = role.id;
    saveConfigs();
    return reply(`✅ Rôle de quarantaine : <@&${role.id}>`);
  }

  if (interaction.commandName === "avis") {
    const note = interaction.options.getInteger("note");
    const msg = interaction.options.getString("message")?.trim();

    const last = avisCooldowns.get(interaction.user.id) || 0;
    const wait = 60_000 - (now() - last);
    if (wait > 0) {
      return reply(`⏳ Tu as déjà laissé un avis il y a moins d'une minute. Réessaie dans ${Math.ceil(wait / 1000)}s.`);
    }
    avisCooldowns.set(interaction.user.id, now());

    const stars = "⭐".repeat(note) + "☆".repeat(5 - note);
    const channel = guild.channels.cache.get(REVIEW_CHANNEL_ID);
    if (!channel || !channel.isTextBased()) {
      return reply("❌ Le salon des avis est introuvable. Signale-le à un admin.");
    }
    const embed = new EmbedBuilder()
      .setTitle("⭐ Nouvel avis sur EASY TUNING")
      .setDescription(
        `**Note :** ${stars} (${note}/5)\n` +
        `**Laisse par :** ${interaction.user.tag}\n` +
        (msg ? `**Message :** *“${msg}”*` : "")
      )
      .setColor(0xf1c40f)
      .setTimestamp();
    await channel.send({ content: `${interaction.member}`, embeds: [embed] });
    return reply(`✅ Merci pour ton avis ! (${stars} — ${note}/5) Il a été posté dans <#${REVIEW_CHANNEL_ID}>.`);
  }
}

/* ------------------------------------------------------------------ */
/*  Bot                                                               */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/*  Bot                                                               */
/* ------------------------------------------------------------------ */

// Le token vient de Discloud/Render/etc. (TOKEN) ou du .env local (DISCORD_TOKEN)
const getToken = () => process.env.TOKEN || process.env.DISCORD_TOKEN || "";

let client = null;
let degraded = false;
let readyFlag = false;

// Keepalive HTTP pour les hébergeurs qui mettent en veille les services
// inactifs (Render, Glitch, etc.). S'active automatiquement s'ils le demandent.
if (process.env.PORT) {
  const server = http.createServer((req, res) => {
    if (req.url === "/status") {
      const body = JSON.stringify({
        ok: true,
        connected: Boolean(readyFlag),
        degraded,
        guilds: client?.guilds?.cache?.size ?? 0,
        uptime: Math.floor(process.uptime()),
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("RaidShield OK");
  });
  server.listen(process.env.PORT, () => {
    console.log(`[RaidShield] Keepalive HTTP actif sur le port ${process.env.PORT}`);
  });
}

const FULL_INTENTS = [
  GatewayIntentBits.Guilds,
  GatewayIntentBits.GuildMembers,
  GatewayIntentBits.GuildModeration,
  GatewayIntentBits.GuildMessages,
  GatewayIntentBits.MessageContent,
];
const DEGRADED_INTENTS = [
  GatewayIntentBits.Guilds,
  GatewayIntentBits.GuildModeration,
  GatewayIntentBits.GuildMessages,
];

function setupEvents(bot) {
  bot.once(Events.ClientReady, async (c) => {
    readyFlag = true;
    console.log(`[RaidShield] Connecté en tant que ${c.user.tag} (${c.user.id})${degraded ? " — MODE DÉGRADÉ" : ""}`);
    c.user.setActivity("🛡️ Anti-raid premium", { type: ActivityType.Watching });

    if (degraded) {
      console.warn(
        "[RaidShield] ⚠️ MODE DÉGRADÉ : les intents privilégiés sont désactivés sur le portail dev.\n" +
          "    Actifs : anti-nuke salons/rôles/bans via audit logs, lockdown manuel.\n" +
          "    Inactifs : anti-spam par contenu, anti-massjoin, protection rôles par audit,\n" +
          "    anti-kick et anti-bots. Active les intents puis relance le bot."
      );
    }

    // Déploiement des commandes slash sur le(s) serveur(s)
    const guildId = process.env.GUILD_ID;
    const targetGuild = guildId ? c.guilds.cache.get(guildId) : c.guilds.cache.first();
    if (targetGuild) {
      await targetGuild.commands.set(commands);
      console.log(`[RaidShield] ${commands.length} commandes déployées sur ${targetGuild.name}`);
      await log(
        targetGuild,
        degraded ? "🛡️ RAID SHIELD DÉMARRÉ (mode dégradé)" : "🛡️ RAID SHIELD DÉMARRÉ",
        degraded
          ? "⚠️ **MODE DÉGRADÉ** : active les intents privilégiés dans le portail dev pour la protection complète.\nTape **/raid status** pour voir l'état, **/raid lockdown** pour verrouiller le serveur."
          : "Protection active. Tape **/raid status** pour voir l'état, **/raid lockdown** pour verrouiller le serveur.",
        degraded ? 0xe8590c : 0x5865f2
      );
    } else {
      console.warn("[RaidShield] Aucun serveur détecté — invite le bot sur un serveur.");
    }
  });

  bot.on(Events.GuildCreate, async (guild) => {
    await guild.commands.set(commands).catch(() => null);
    console.log(`[RaidShield] Rejoint ${guild.name} — commandes déployées.`);
    await log(guild, "🛡️ RAID SHIELD DÉMARRÉ", "Protection active. Tape **/raid status** pour voir l'état.", 0x5865f2);
  });

  bot.on(Events.GuildMemberAdd, onMemberAdd);
  bot.on(Events.MessageCreate, onMessage);
  bot.on(Events.ChannelCreate, onChannelCreate);
  bot.on(Events.ChannelDelete, onChannelDelete);
  bot.on(Events.RoleCreate, onRoleCreate);
  bot.on(Events.RoleDelete, onRoleDelete);
  bot.on(Events.RoleUpdate, onRoleUpdate);
  bot.on(Events.GuildBanAdd, onBanAdd);
  bot.on(Events.GuildMemberUpdate, onMemberUpdate);

  // Détection anti-kick : le départ d'un membre déclenche l'audit log si c'est un kick
  bot.on(Events.GuildMemberRemove, async (member) => {
    if (!member.guild) return;
    const config = configOf(member.guild.id);
    if (!config.enabled) return;
    const audit = await member.guild.fetchAuditLogs({ type: AuditLogEvent.MemberKick, limit: 1 }).catch(() => null);
    const entry = audit?.entries.first();
    if (entry && now() - entry.createdTimestamp < 8_000) {
      await onKickDetected(member, true);
    }
  });

  bot.on(Events.InteractionCreate, handleInteraction);
}

function memberGuildFor(guildId) {
  return client?.guilds?.cache?.get(guildId) ?? null;
}

// Nettoyage périodique des états anti-spam et expiration des verrous
setInterval(() => {
  for (const [guildId, st] of states) {
    const config = guildConfigs.get(guildId);
    if (!config) continue;
    prune(st.windows.channelCreate, config.thresholds.actionWindow);
    prune(st.windows.channelDelete, config.thresholds.actionWindow);
    prune(st.windows.roleCreate, config.thresholds.actionWindow);
    prune(st.windows.roleDelete, config.thresholds.actionWindow);
    prune(st.windows.ban, config.thresholds.actionWindow);
    prune(st.windows.kick, config.thresholds.actionWindow);
    prune(st.windows.join, config.thresholds.actionWindow);
    for (const s of st.spam.values()) {
      prune(s.times, 5_000);
    }
    if (config.lockdown && config.lockdownUntil && now() > config.lockdownUntil) {
      const g = memberGuildFor(guildId);
      if (g) setLockdown(g, 0, false);
    }
    if (config.raidMode && config.raidModeUntil && now() > config.raidModeUntil) {
      const g = memberGuildFor(guildId);
      if (g) disableRaidMode(g);
    }
  }
}, 30_000);

function startDegraded() {
  console.warn("[RaidShield] Redémarrage en MODE DÉGRADÉ (intents privilégiés désactivés sur le portail).");
  degraded = true;
  client = new Client({ intents: DEGRADED_INTENTS, partials: [Partials.Message, Partials.GuildMember, Partials.User, Partials.Channel] });
  setupEvents(client);
  client.login(getToken()).catch((err) => {
    console.error("[RaidShield] Échec de connexion même en mode dégradé:", err?.message || err);
    process.exit(1);
  });
}

client = new Client({ intents: FULL_INTENTS, partials: [Partials.Message, Partials.GuildMember, Partials.User, Partials.Channel] });
setupEvents(client);

process.on("unhandledRejection", (reason) => {
  const msg = String(reason?.message || reason || "");
  if (/disallowed intents/i.test(msg) && !degraded) {
    client?.destroy().catch(() => null);
    startDegraded();
    return;
  }
  console.error("[RaidShield] unhandledRejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[RaidShield] uncaughtException:", err);
});

loadConfigs();
if (!getToken()) {
  console.error("[RaidShield] TOKEN manquant — définis la variable d'environnement TOKEN (ou DISCORD_TOKEN dans .env) puis relance.");
  process.exit(1);
}

// Mode diagnostic (aucune connexion) : valide la sérialisation des commandes
if (process.env.TEST_SLASH === "1") {
  let bad = 0;
  for (const cmd of commands) {
    try {
      cmd.toJSON();
      console.log("OK /" + cmd.name);
    } catch (e) {
      bad++;
      console.error("INVALIDE /" + cmd.name + " :: " + (e?.message || e));
    }
  }
  console.log(bad ? `=> ${bad} commande(s) invalide(s)` : "=> Toutes les commandes sont valides.");
  process.exit(bad ? 1 : 0);
}

client.login(getToken()).catch((err) => {
  const msg = String(err?.message || err || "");
  if (/disallowed intents/i.test(msg) && !degraded) {
    client?.destroy().catch(() => null);
    startDegraded();
    return;
  }
  console.error("[RaidShield] Échec de connexion:", err?.message || err);
  process.exit(1);
});

setTimeout(() => {
  if (!readyFlag) {
    console.error("[RaidShield] ⚠️ Aucun signal 'prêt' de Discord après 120s — connexion bloquée.");
  } else {
    console.log("[RaidShield] ✅ Connexion Discord confirmée.");
  }
}, 120_000);