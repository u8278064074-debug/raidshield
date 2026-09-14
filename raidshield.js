/**
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *  âš”ï¸ RAID SHIELD â€” Bot anti-raid premium pour Discord
 *  Protection complÃ¨te : anti-nuke, anti-spam, anti-massjoin,
 *  protection des rÃ´les, journalisation, mode RAID & lockdown.
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
const CITIZEN_ROLE_ID = "1548792320260972564"; // rÃ´le ðŸ‘¥ Citoyen (auto-attribuÃ© aux nouveaux)
const REVIEW_CHANNEL_ID = "1548887315865149460"; // â­-avis (les /avis y sont postÃ©s)
const avisCooldowns = new Map(); // userId -> timestamp du dernier /avis

/* ------------------------------------------------------------------ */
/*  Configuration par dÃ©faut (chaque serveur peut la modifier)         */
/* ------------------------------------------------------------------ */

const DEFAULT_CONFIG = {
  enabled: true,
  logChannel: null, // ID du salon de logs
  quarantineRole: null, // rÃ´le de quarantaine (optionnel)
  lockdown: false,
  lockdownUntil: null,
  raidMode: false,
  raidModeUntil: null,
  thresholds: {
    channelCreate: 4, // crÃ©ations de salons en 10s â†’ raid
    channelDelete: 4, // suppressions de salons en 10s â†’ raid
    roleCreate: 3, // crÃ©ations de rÃ´les en 10s â†’ raid
    roleDelete: 3, // suppressions de rÃ´les en 10s â†’ raid
    ban: 3, // bans en 10s â†’ raid
    kick: 4, // kicks en 10s â†’ raid
    spam: 5, // messages en 5s â†’ avertissement anti-spam
    duplicate: 3, // messages identiques en 5s â†’ anti-dup
    joinRush: 6, // arrivÃ©es en 10s â†’ raid join
    botAdd: 2, // bots ajoutÃ©s en 30s â†’ raid bots
    newAccountDays: 3, // comptes plus jeunes que Ã§a = suspect
    actionWindow: 10_000, // fenÃªtre de dÃ©tection (ms)
  },
  punishments: {
    default: "timeout", // timeout | kick | ban
    timeoutMinutes: 60,
    nuke: "ban", // punition pour destruction de salons/rÃ´les/bans massifs
  },
  spam: {
    invites: true, // bloquer les invitations Discord dans les messages
    everyone: true, // bloquer @everyone / @here
    maxMentions: 4, // mentions autorisÃ©es par message (non-everyone)
  },
  whitelistUsers: [], // jamais punis
  whitelistRoles: [], // membres avec ce rÃ´le = jamais punis
  protectedRoles: [], // rÃ´les protÃ©gÃ©s : toute modification non staff = rollback
};

/* ------------------------------------------------------------------ */
/*  Ã‰tat en mÃ©moire                                                    */
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
/*  Configuration (persistÃ©e dans raidshield-config.json)              */
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
  ban: async (m) => (m.bannable ? m.ban({ reason: "RaidShield â€” raid dÃ©tectÃ© | " + (m._reason || "") }).catch(() => null) : null),
  kick: async (m) => (m.kickable ? m.kick("RaidShield â€” raid dÃ©tectÃ© | " + (m._reason || "")).catch(() => null) : null),
  timeout: (m) => (m.moderatable ? m.timeout((m._minutes || 60) * 60_000, "RaidShield â€” raid dÃ©tectÃ© | " + (m._reason || "")).catch(() => null) : null),
};

async function punish(member, level, reason, minutes = 60) {
  if (!member || !member.id) return false;
  const config = configOf(member.guild.id);
  if (isStaff(member) || isWhitelisted(member, config)) {
    await punishLog(member.guild, `âš ï¸ Tentative non punie`, `${member.user.tag} (${member.id}) â€” ${reason} (staff / whitelistÃ©)`);
    return false;
  }
  member._reason = reason;
  member._minutes = minutes;
  const fn = CAN_PUNISH_NAMES[level] || CAN_PUNISH_NAMES.timeout;
  await fn(member);
  await punishLog(member.guild, level.toUpperCase(), `${member.user?.tag || member.id} â€” ${reason}`, level === "ban" ? 0xdb2a2a : level === "kick" ? 0xe8590c : 0xf2c053);
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
    "ðŸš¨ MODE RAID ACTIVÃ‰",
    `**${reason}**\nLe serveur est en Ã©tat d'alerte pendant **${minutes} min** :\nâ€¢ Tout nouveau membre sera mis en timeout immÃ©diatement\nâ€¢ Toute crÃ©ation/suppression de salon et de rÃ´le sera annulÃ©e\nâ€¢ Toute punition est appliquÃ©e automatiquement\nUtilise **/raid unlock** manuellement si nÃ©cessaire.`,
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
  return log(guild, "âœ… SÃ‰CURITÃ‰ RÃ‰TABLIE", "Le mode raid est dÃ©sactivÃ©. Les mesures automatiques sont levÃ©es.", 0x2ecc71);
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
    enable ? "ðŸ”’ LOCKDOWN ACTIVÃ‰" : "ðŸ”“ LOCKDOWN DÃ‰SACTIVÃ‰",
    enable
      ? `Tout nouveau membre sera mis en timeout pendant **${minutes} min** jusqu'Ã  <t:${Math.floor(config.lockdownUntil / 1000)}:R>.`
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

  // Rollback : supprime les salons crÃ©Ã©s en rafale
  let rolledBack = 0;
  for (const c of guild.channels.cache.filter((ch) => ch.id !== channel.id && now() - ch.createdTimestamp < 30_000)) {
    if (rolledBack >= 10) break;
    if (c.deletable) {
      await c.delete("RaidShield â€” suppression salons crÃ©Ã©s pendant le raid").catch(() => null);
      rolledBack++;
    }
  }
  if (channel.deletable) {
    await channel.delete("RaidShield â€” salon crÃ©Ã© pendant un raid").catch(() => null);
    rolledBack++;
  }

  await logAlert(
    guild,
    "ðŸš§ SALONS CRÃ‰Ã‰S EN MASSE",
    `**${count} salons** crÃ©Ã©s en ${config.thresholds.actionWindow / 1000}s â†’ **${rolledBack} annulÃ©(s)**, fautif : ${executor ?? "inconnu"} (<@${channel.id}>)`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `CrÃ©ation en masse de salons (${count} en ${config.thresholds.actionWindow / 1000}s)`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "CrÃ©ation en masse de salons");
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

  // Rollback : recrÃ©e le canal supprimÃ©
  try {
    await guild.channels.create({
      name: channel.name,
      type: channel.type === ChannelType.GuildVoice || channel.type === ChannelType.GuildStageVoice
        ? channel.type
        : ChannelType.GuildText,
      parent: channel.parentId ?? undefined,
      reason: "RaidShield â€” restauration du salon supprimÃ©",
    });
  } catch { /* permis manquants */ }

  await logAlert(
    guild,
    "ðŸ’¥ SALONS SUPPRIMÃ‰S EN MASSE",
    `**${count} suppressions** dÃ©tectÃ©es â†’ salon restaurÃ©, fautif : ${executor ?? "inconnu"}`,
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
    await role.delete("RaidShield â€” rÃ´le crÃ©Ã© pendant un raid").catch(() => null);
  }

  await logAlert(
    guild,
    "ðŸŽ­ RÃ”LES CRÃ‰Ã‰S EN MASSE",
    `**${count} rÃ´les** crÃ©Ã©s â†’ supprimÃ©s, fautif : ${executor ?? "inconnu"}`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `CrÃ©ation en masse de rÃ´les (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "CrÃ©ation en masse de rÃ´les");
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
      reason: "RaidShield â€” restauration du rÃ´le supprimÃ©",
    });
  } catch { /* permis manquants */ }

  await logAlert(
    guild,
    "ðŸ’¥ RÃ”LES SUPPRIMÃ‰S EN MASSE",
    `**${count} suppressions** dÃ©tectÃ©es â†’ rÃ´le **${role.name}** restaurÃ©, fautif : ${executor ?? "inconnu"}`,
    0xdb2a2a
  );
  if (!config.raidMode) await enableRaidMode(guild, `Suppressions en masse de rÃ´les (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Suppression en masse de rÃ´les");
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
  if (executor?.id === client.user?.id) return; // le bot agit lui-mÃªme
  if (isStaff(executor)) return;

  const permChanged = oldRole.permissions.bitfield !== newRole.permissions.bitfield;
  const roleIsProtected = roleNeedsProtection(newRole, config);

  if (permChanged && roleIsProtected) {
    // Rollback des permissions
    await newRole.setPermissions(oldRole.permissions.bitfield, "RaidShield â€” restauration des permissions").catch(() => null);
    await logAlert(
      guild,
      "ðŸ›¡ï¸ PERMISSIONS MODIFIÃ‰ES",
      `Le rÃ´le **${newRole.name}** a reÃ§u des permissions sensibles â†’ **annulÃ©**, fautif : ${executor ?? "inconnu"}`,
      0xdb2a2a
    );
    if (executor) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Modification des permissions d'un rÃ´le sensible");
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
    await guild.members.unban(ban.user.id, "RaidShield â€” ban de masse annulÃ©").catch(() => null);
  } catch { /* pas le droit de unban */ }

  await logAlert(
    guild,
    "â›” BANS EN MASSE",
    `**${count} bans** dÃ©tectÃ©s â†’ annulÃ©s et membres restaurÃ©s, fautif : ${executor ?? "inconnu"}`,
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
    "ðŸ‘¢ KICKS EN MASSE",
    `**${count} kicks** dÃ©tectÃ©s â†’ alerte, fautif : ${executor ?? "inconnu"}`,
    0xe8590c
  );
  if (!config.raidMode) await enableRaidMode(guild, `Kicks en masse (${count})`);
  if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Kicks en masse");
}

async function greetNewMember(member) {
  const guild = member.guild;
  const config = configOf(guild.id);
  if (!config.enabled || config.lockdown || config.raidMode) return;

  // Auto-attribution du rÃ´le Citoyen
  try {
    const role = guild.roles.cache.get(CITIZEN_ROLE_ID);
    if (role && !member.roles.cache.has(role.id)) {
      await member.roles.add(role.id, "RaidShield â€” rÃ´le Citoyen de bienvenue");
    }
  } catch { /* permissions insuffisantes */ }

  // Message de bienvenue
  try {
    const channel = guild.channels.cache.get(WELCOME_CHANNEL_ID);
    if (!channel || !channel.isTextBased()) return;
    const embed = new EmbedBuilder()
      .setTitle("ðŸŽ‰ Bienvenue sur EASY TUNING !")
      .setDescription(
        `Bienvenue **${member.user.username}** sur le serveur ! ðŸš—ðŸ’¨\n\n` +
        `RÃ´le **ðŸ‘¥ Citoyen** attribuÃ© automatiquement.` +
        `\nPasse nous dire bonjour, explore les salons et bon jeu Ã  toi !`
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
        "ðŸ¤– BOTS AJOUTÃ‰S",
        `**${count} bots** ajoutÃ©s en 30s â†’ bots retirÃ©s, fautif : ${executor ?? "inconnu"}`,
        0xdb2a2a
      );
      if (member.kickable) await member.kick("RaidShield â€” ajout en masse de bots");
      if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.nuke, "Ajout en masse de bots");
      if (!config.raidMode) await enableRaidMode(guild, `Ajout en masse de bots (${count})`);
    }
    return;
  }

  prune(st.windows.join, config.thresholds.actionWindow);
  st.windows.join.push(now());
  const joinCount = st.windows.join.length;

  // Lockdown / raid mode â†’ timeout immÃ©diat du nouvel arrivant
  if (config.lockdown || config.raidMode) {
    const minutes = config.punishments.timeoutMinutes;
    await member.timeout(minutes * 60_000, "RaidShield â€” lockdown actif").catch(() => null);
    await log(guild, "ðŸ”’ NOUVEL ARRIVANT VERROUILLÃ‰", `${member.user.tag} rejoint pendant le lockdown â†’ timeout ${minutes} min`, 0xe67e22);
    return;
  }

  // Rafle de comptes jeunes
  if (joinCount >= config.thresholds.joinRush && config.thresholds.joinRush > 0) {
    const accountAge = (now() - member.user.createdTimestamp) / 86_400_000;
    if (accountAge < config.thresholds.newAccountDays) {
      await member.timeout(config.punishments.timeoutMinutes * 60_000, "RaidShield â€” rafle de nouveaux comptes").catch(() => null);
      await logAlert(
        guild,
        "ðŸš¨ RAFLE DE NOUVEAUX COMPTES",
        `**${joinCount} membres** en ${config.thresholds.actionWindow / 1000}s, compte Ã¢gÃ© de **${Math.floor(accountAge)}j** â†’ timeout.`,
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
      await newMember.roles.remove(role.id, "RaidShield â€” attribution d'un rÃ´le sensible annulÃ©e").catch(() => null);
      await logAlert(
        guild,
        "ðŸ›¡ï¸ RÃ”LE SENSIBLE ATTRIBUÃ‰",
        `**${role.name}** retirÃ© de ${newMember.user.tag}, fautif : ${executor ?? "inconnu"}`,
        0xdb2a2a
      );
      if (executor && !isStaff(executor)) await punish(await guild.members.fetch(executor.id).catch(() => null), config.punishments.default, "Attribution d'un rÃ´le sensible");
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
    await punish(member, "kick", `Anti-spam (3e infraction) â€” ${reason}`);
  } else if (s.strikes >= 2) {
    await punish(member, "timeout", `Anti-spam (2e infraction) â€” ${reason}`, 60);
  } else {
    await punish(member, "timeout", `Anti-spam â€” ${reason}`, 10);
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
    await log(guild, "ðŸš« @EVERYONE BLOQUÃ‰", `${member?.user.tag} a tentÃ© d'utiliser @everyone/@here`, 0xe8590c);
    await spamPunish(member, config, "@everyone/@here");
    return;
  }

  // Anti invitations Discord
  if (config.spam.invites && /(discord\.(gg|io|me|li)\/\S+|discord(app)?\.com\/invite\/\S+)/i.test(message.content)) {
    await message.delete().catch(() => null);
    await log(guild, "ðŸš« INVITATION BLOQUÃ‰E", `${member?.user.tag} a postÃ© une invitation Discord`, 0xe8590c);
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

  // FenÃªtre anti-spam / anti-doublon
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

const PERM_REF = "Les administrateurs, les whitelistÃ©s et RaidShield lui-mÃªme ne sont jamais punis.";

const commands = [
  new SlashCommandBuilder()
    .setName("raid")
    .setDescription("Centre de contrÃ´le anti-raid (statut, lockdown, config)")
    .addSubcommand((s) => s.setName("status").setDescription("Ã‰tat actuel de la protection"))
    .addSubcommand((s) =>
      s.setName("lockdown").setDescription("Verrouille le serveur : les nouveaux arrivants sont mis en timeout")
        .addIntegerOption((o) => o.setName("minutes").setDescription("DurÃ©e en minutes (dÃ©faut 60)").setMinValue(1).setMaxValue(1440)))
    .addSubcommand((s) => s.setName("unlock").setDescription("LÃ¨ve le lockdown et le mode raid"))
    .addSubcommand((s) =>
      s.setName("config").setDescription("Ajuste un seuil de protection")
        .addStringOption((o) =>
          o.setName("cle").setDescription("ClÃ© de configuration").setRequired(true)
            .addChoices(
              { name: "Seuil : salons crÃ©Ã©s (10s)", value: "channelCreate" },
              { name: "Seuil : salons supprimÃ©s (10s)", value: "channelDelete" },
              { name: "Seuil : rÃ´les crÃ©Ã©s (10s)", value: "roleCreate" },
              { name: "Seuil : rÃ´les supprimÃ©s (10s)", value: "roleDelete" },
              { name: "Seuil : bans (10s)", value: "ban" },
              { name: "Seuil : kicks (10s)", value: "kick" },
              { name: "Anti-spam : messages / 5s", value: "spam" },
              { name: "Anti-spam : doublons / 5s", value: "duplicate" },
              { name: "Seuil : rafle de connexions (10s)", value: "joinRush" },
              { name: "Suspect : Ã¢ge du compte (jours)", value: "newAccountDays" },
              { name: "Seuil : bots ajoutÃ©s (30s)", value: "botAdd" },
              { name: "FenÃªtre de dÃ©tection (ms)", value: "actionWindow" },
              { name: "Punition par dÃ©faut (timeout/kick/ban)", value: "punishDefault" },
              { name: "DurÃ©e du timeout (minutes)", value: "timeoutMinutes" },
              { name: "Punition anti-nuke (timeout/kick/ban)", value: "nukePunish" },
            ))
        .addStringOption((o) => o.setName("valeur").setDescription("Nouvelle valeur").setRequired(true)))
    .addSubcommand((s) =>
      s.setName("punish").setDescription("Punition par dÃ©faut pour un spammeur")
        .addStringOption((o) =>
          o.setName("mode").setDescription("timeout, kick ou ban").setRequired(true)
            .addChoices(
              { name: "timeout (recommandÃ©)", value: "timeout" },
              { name: "kick", value: "kick" },
              { name: "ban", value: "ban" }))),
  new SlashCommandBuilder()
    .setName("whitelist")
    .setDescription("GÃ¨re la liste des membres/rÃ´les jamais punis par RaidShield")
    .addSubcommand((s) => s.setName("add").setDescription("Ajoute un membre Ã  la whitelist").addUserOption((o) => o.setName("user").setDescription("Membre").setRequired(true)))
    .addSubcommand((s) => s.setName("remove").setDescription("Retire un membre de la whitelist").addUserOption((o) => o.setName("user").setDescription("Membre").setRequired(true)))
    .addSubcommand((s) => s.setName("list").setDescription("Liste les membres whitelistÃ©s"))
    .addSubcommand((s) => s.setName("role").setDescription("Ajoute un rÃ´le Ã  la whitelist").addRoleOption((o) => o.setName("role").setDescription("RÃ´le").setRequired(true)))
    .addSubcommand((s) => s.setName("roledel").setDescription("Retire un rÃ´le de la whitelist").addRoleOption((o) => o.setName("role").setDescription("RÃ´le").setRequired(true))),
  new SlashCommandBuilder()
    .setName("protected")
    .setDescription("RÃ´les protÃ©gÃ©s : toute modif non-staff sera annulÃ©e")
    .addSubcommand((s) => s.setName("add").setDescription("ProtÃ¨ge un rÃ´le").addRoleOption((o) => o.setName("role").setDescription("RÃ´le").setRequired(true)))
    .addSubcommand((s) => s.setName("remove").setDescription("Retire la protection d'un rÃ´le").addRoleOption((o) => o.setName("role").setDescription("RÃ´le").setRequired(true)))
    .addSubcommand((s) => s.setName("list").setDescription("Liste les rÃ´les protÃ©gÃ©s")),
  new SlashCommandBuilder()
    .setName("logs")
    .setDescription("Configure le salon de journalisation")
    .addSubcommand((s) => s.setName("set").setDescription("Salon oÃ¹ sont envoyÃ©s les logs").addChannelOption((o) => o.setName("salon").setDescription("Salon de logs").setRequired(true)))
    .addSubcommand((s) => s.setName("unset").setDescription("Supprime le salon de logs configurÃ©")),
  new SlashCommandBuilder()
    .setName("qrole")
    .setDescription("DÃ©finit le rÃ´le de quarantaine appliquÃ© pendant un raid")
    .addStringOption((o) => o.setName("role").setDescription("ID du rÃ´le, ou 'aucun'").setRequired(true)),
  new SlashCommandBuilder()
    .setName("avis")
    .setDescription("Laisse un avis sur le serveur (note de 1 Ã  5 Ã©toiles)")
    .addIntegerOption((o) => o.setName("note").setDescription("Note de 1 Ã  5 Ã©toiles").setRequired(true).setMinValue(1).setMaxValue(5))
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
      await interaction.reply({ content: "âŒ Tu as besoin de la permission **GÃ©rer le serveur** pour cette commande.", ephemeral: true });
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
        `ðŸ›¡ï¸ **Ã‰tat** : ${config.enabled ? "actif" : "dÃ©sactivÃ©"}`,
        `ðŸš¨ **Mode RAID** : ${config.raidMode ? "ACTIF jusqu'Ã  <t:" + Math.floor(config.raidModeUntil / 1000) + ":T>" : "inactif"}`,
        `ðŸ”’ **Lockdown** : ${config.lockdown ? "ACTIF jusqu'Ã  <t:" + Math.floor(config.lockdownUntil / 1000) + ":T>" : "inactif"}`,
        ``,
        `ðŸ“Š **Seuils (fenÃªtre ${(th.actionWindow / 1000).toFixed(0)}s)** :`,
        `     Salons crÃ©Ã©s  â†’ ${th.channelCreate}`,
        `     Salons suppr. â†’ ${th.channelDelete}`,
        `     RÃ´les crÃ©Ã©s   â†’ ${th.roleCreate}`,
        `     RÃ´les suppr.  â†’ ${th.roleDelete}`,
        `     Bans  â†’ ${th.ban}   Kicks â†’ ${th.kick}`,
        `     Connexions â†’ ${th.joinRush}   Bots ajoutÃ©s â†’ ${th.botAdd}`,
        `     Anti-spam  â†’ ${th.spam} msg / 5s   Doublons â†’ ${th.duplicate}`,
        `     Compte suspect â†’ < ${th.newAccountDays} jours`,
        ``,
        `âš–ï¸ **Punitions** : dÃ©faut = \`${config.punishments.default}\`, nuke = \`${config.punishments.nuke}\`, timeout = ${config.punishments.timeoutMinutes} min`,
        `ðŸ›¡ï¸ **Whitelist** : ${config.whitelistUsers.length} membres, ${config.whitelistRoles.length} rÃ´les`,
        `ðŸ” **RÃ´les protÃ©gÃ©s** : ${config.protectedRoles.length}`,
        `ðŸ“¢ **Salon de logs** : ${config.logChannel ? `<#${config.logChannel}>` : "automatique"}`,
      ];
      return reply(parts.join("\n"));
    }

    if (sub === "lockdown") {
      const minutes = interaction.options.getInteger("minutes") ?? 60;
      await setLockdown(guild, minutes, true);
      return reply(`ðŸ”’ Lockdown dÃ©marrÃ© pour ${minutes} min. Les nouveaux arrivants seront mis en timeout automatiquement.`);
    }

    if (sub === "unlock") {
      disableRaidMode(guild);
      return reply("ðŸ”“ Protection dÃ©sactivÃ©e. L'accÃ¨s est de nouveau normal.");
    }

    if (sub === "config") {
      const key = interaction.options.getString("cle");
      const raw = interaction.options.getString("valeur").trim();
      if (key === "punishDefault" || key === "nukePunish") {
        if (!["timeout", "kick", "ban"].includes(raw)) return reply("âŒ Valeur invalide (timeout, kick, ban).");
        config.punishments[key === "punishDefault" ? "default" : "nuke"] = raw;
      } else if (key === "timeoutMinutes") {
        config.punishments.timeoutMinutes = Math.max(1, Math.min(1440, parseInt(raw) || 60));
      } else {
        const n = parseInt(raw);
        if (Number.isNaN(n) || n < 0) return reply("âŒ Valeur numÃ©rique invalide.");
        config.thresholds[key] = n;
      }
      saveConfigs();
      return reply(`âœ… \`${key}\` mis Ã  jour â†’ **${raw}**`);
    }

    if (sub === "punish") {
      const mode = interaction.options.getString("mode");
      config.punishments.default = mode;
      saveConfigs();
      return reply(`âœ… Punition par dÃ©faut â†’ **${mode}**`);
    }
  }

  if (interaction.commandName === "whitelist") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();
    if (sub === "add") {
      const u = interaction.options.getUser("user");
      if (!config.whitelistUsers.includes(u.id)) config.whitelistUsers.push(u.id);
      saveConfigs();
      return reply(`âœ… ${u.tag} ajoutÃ© Ã  la whitelist.`);
    }
    if (sub === "remove") {
      const u = interaction.options.getUser("user");
      config.whitelistUsers = config.whitelistUsers.filter((id) => id !== u.id);
      saveConfigs();
      return reply(`âœ… ${u.tag} retirÃ© de la whitelist.`);
    }
    if (sub === "list") {
      const names = config.whitelistUsers.map((id) => `<@${id}>`).join(", ") || "Aucun";
      const roles = config.whitelistRoles.map((id) => `<@&${id}>`).join(", ") || "Aucun";
      return reply(`ðŸ›¡ï¸ **Membres** : ${names}\nðŸ›¡ï¸ **RÃ´les** : ${roles}`);
    }
    if (sub === "role") {
      const r = interaction.options.getRole("role");
      if (!config.whitelistRoles.includes(r.id)) config.whitelistRoles.push(r.id);
      saveConfigs();
      return reply(`âœ… RÃ´le <@&${r.id}> whitelistÃ©.`);
    }
    if (sub === "roledel") {
      const r = interaction.options.getRole("role");
      config.whitelistRoles = config.whitelistRoles.filter((id) => id !== r.id);
      saveConfigs();
      return reply(`âœ… RÃ´le <@&${r.id}> retirÃ© de la whitelist.`);
    }
  }

  if (interaction.commandName === "protected") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();
    if (sub === "add") {
      const r = interaction.options.getRole("role");
      if (!config.protectedRoles.includes(r.id)) config.protectedRoles.push(r.id);
      saveConfigs();
      return reply(`ðŸ” RÃ´le <@&${r.id}> protÃ©gÃ© : toute modif non-staff sera annulÃ©e.`);
    }
    if (sub === "remove") {
      const r = interaction.options.getRole("role");
      config.protectedRoles = config.protectedRoles.filter((id) => id !== r.id);
      saveConfigs();
      return reply(`ðŸ”“ RÃ´le <@&${r.id}> n'est plus protÃ©gÃ©.`);
    }
    if (sub === "list") {
      const roles = config.protectedRoles.map((id) => `<@&${id}>`).join(", ") || "Aucun";
      return reply(`ðŸ” **RÃ´les protÃ©gÃ©s** : ${roles}`);
    }
  }

  if (interaction.commandName === "logs") {
    if (!(await requireAdmin())) return;
    const sub = interaction.options.getSubcommand();
    if (sub === "set") {
      const ch = interaction.options.getChannel("salon");
      config.logChannel = ch.id;
      saveConfigs();
      return reply(`ðŸ“¢ Logs â†’ <#${ch.id}>`);
    }
    if (sub === "unset") {
      config.logChannel = null;
      saveConfigs();
      return reply("ðŸ“¢ Salon de logs dÃ©fini sur **automatique** (recherche d'un salon 'logs').");
    }
  }

  if (interaction.commandName === "qrole") {
    if (!(await requireAdmin())) return;
    const raw = interaction.options.getString("role");
    if (/^(aucun|none|null)$/i.test(raw)) {
      config.quarantineRole = null;
      saveConfigs();
      return reply("âœ… RÃ´le de quarantaine dÃ©sactivÃ©.");
    }
    const role = await guild.roles.fetch(raw).catch(() => null);
    if (!role) return reply("âŒ RÃ´le introuvable. Donne l'**ID** du rÃ´le (ParamÃ¨tres du rÃ´le â†’ clic droit).");
    config.quarantineRole = role.id;
    saveConfigs();
    return reply(`âœ… RÃ´le de quarantaine : <@&${role.id}>`);
  }

  if (interaction.commandName === "avis") {
    const note = interaction.options.getInteger("note");
    const msg = interaction.options.getString("message")?.trim();

    const last = avisCooldowns.get(interaction.user.id) || 0;
    const wait = 60_000 - (now() - last);
    if (wait > 0) {
      return reply(`â³ Tu as dÃ©jÃ  laissÃ© un avis il y a moins d'une minute. RÃ©essaie dans ${Math.ceil(wait / 1000)}s.`);
    }
    avisCooldowns.set(interaction.user.id, now());

    const stars = "â­".repeat(note) + "â˜†".repeat(5 - note);
    const channel = guild.channels.cache.get(REVIEW_CHANNEL_ID);
    if (!channel || !channel.isTextBased()) {
      return reply("âŒ Le salon des avis est introuvable. Signale-le Ã  un admin.");
    }
    const embed = new EmbedBuilder()
      .setTitle("â­ Nouvel avis sur EASY TUNING")
      .setDescription(
        `**Note :** ${stars} (${note}/5)\n` +
        `**Laisse par :** ${interaction.user.tag}\n` +
        (msg ? `**Message :** *â€œ${msg}â€*` : "")
      )
      .setColor(0xf1c40f)
      .setTimestamp();
    await channel.send({ content: `${interaction.member}`, embeds: [embed] });
    return reply(`âœ… Merci pour ton avis ! (${stars} â€” ${note}/5) Il a Ã©tÃ© postÃ© dans <#${REVIEW_CHANNEL_ID}>.`);
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
let loginState = { at: 0, ok: false, error: null };
let wsDiag = { closes: [], errors: [] };
let netRes = { ok: null, error: null, tested: false };

async function testNetwork() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetch("https://discord.com/api/v10/gateway", {
      headers: { "User-Agent": "DiscordBot (RaidShield, 1.0.0)" },
      signal: controller.signal,
    });
    clearTimeout(timer);
    return { ok: true, status: res.status };
  } catch (e) {
    clearTimeout(timer);
    return { ok: false, error: String(e?.message || e) };
  }
}
setInterval(async () => {
  const r = await testNetwork();
  netRes = { ...r, tested: true };
}, 60_000);

// Keepalive HTTP pour les hÃ©bergeurs qui mettent en veille les services
// inactifs (Render, Glitch, etc.). S'active automatiquement s'ils le demandent.
if (process.env.PORT) {
  const server = http.createServer((req, res) => {
    if (req.url === "/status") {
      const body = JSON.stringify({
        ok: true,
        connected: Boolean(readyFlag),
        degraded,
        guilds: client?.guilds?.cache?.size ?? 0,
        wsStatus: client?.ws?.status ?? null,
        ws: wsDiag,
        net: netRes,
        login: loginState,
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
    loginState.ok = true;
    loginState.error = null;
    console.log(`[RaidShield] ConnectÃ© en tant que ${c.user.tag} (${c.user.id})${degraded ? " â€” MODE DÃ‰GRADÃ‰" : ""}`);
    c.user.setActivity("ðŸ›¡ï¸ Anti-raid premium", { type: ActivityType.Watching });

    if (degraded) {
      console.warn(
        "[RaidShield] âš ï¸ MODE DÃ‰GRADÃ‰ : les intents privilÃ©giÃ©s sont dÃ©sactivÃ©s sur le portail dev.\n" +
          "    Actifs : anti-nuke salons/rÃ´les/bans via audit logs, lockdown manuel.\n" +
          "    Inactifs : anti-spam par contenu, anti-massjoin, protection rÃ´les par audit,\n" +
          "    anti-kick et anti-bots. Active les intents puis relance le bot."
      );
    }

    // DÃ©ploiement des commandes slash sur le(s) serveur(s)
    const guildId = process.env.GUILD_ID;
    const targetGuild = guildId ? c.guilds.cache.get(guildId) : c.guilds.cache.first();
    if (targetGuild) {
      await targetGuild.commands.set(commands);
      console.log(`[RaidShield] ${commands.length} commandes dÃ©ployÃ©es sur ${targetGuild.name}`);
      await log(
        targetGuild,
        degraded ? "ðŸ›¡ï¸ RAID SHIELD DÃ‰MARRÃ‰ (mode dÃ©gradÃ©)" : "ðŸ›¡ï¸ RAID SHIELD DÃ‰MARRÃ‰",
        degraded
          ? "âš ï¸ **MODE DÃ‰GRADÃ‰** : active les intents privilÃ©giÃ©s dans le portail dev pour la protection complÃ¨te.\nTape **/raid status** pour voir l'Ã©tat, **/raid lockdown** pour verrouiller le serveur."
          : "Protection active. Tape **/raid status** pour voir l'Ã©tat, **/raid lockdown** pour verrouiller le serveur.",
        degraded ? 0xe8590c : 0x5865f2
      );
    } else {
      console.warn("[RaidShield] Aucun serveur dÃ©tectÃ© â€” invite le bot sur un serveur.");
    }
  });

  bot.on(Events.GuildCreate, async (guild) => {
    await guild.commands.set(commands).catch(() => null);
    console.log(`[RaidShield] Rejoint ${guild.name} â€” commandes dÃ©ployÃ©es.`);
    await log(guild, "ðŸ›¡ï¸ RAID SHIELD DÃ‰MARRÃ‰", "Protection active. Tape **/raid status** pour voir l'Ã©tat.", 0x5865f2);
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

  // DÃ©tection anti-kick : le dÃ©part d'un membre dÃ©clenche l'audit log si c'est un kick
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

  bot.on(Events.ShardDisconnect, (closeEvent, id) => {
    wsDiag.closes.push({ code: closeEvent?.code ?? null, at: Math.floor(process.uptime()) });
    console.error(`[RaidShield] WebSocket fermé (shard ${id}) — code=${closeEvent?.code}`);
  });
  bot.on(Events.ShardError, (err, id) => {
    wsDiag.errors.push({ error: String(err?.message || err || ""), at: Math.floor(process.uptime()) });
    console.error(`[RaidShield] WebSocket erreur (shard ${id}) : ${err?.message || err}`);
  });
  bot.on(Events.ShardReconnecting, (id) => {
    console.error(`[RaidShield] WebSocket reconnexion en cours (shard ${id})`);
  });
}

function memberGuildFor(guildId) {
  return client?.guilds?.cache?.get(guildId) ?? null;
}

// Nettoyage pÃ©riodique des Ã©tats anti-spam et expiration des verrous
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
  console.warn("[RaidShield] RedÃ©marrage en MODE DÃ‰GRADÃ‰ (intents privilÃ©giÃ©s dÃ©sactivÃ©s sur le portail).");
  degraded = true;
  client = new Client({ intents: DEGRADED_INTENTS, partials: [Partials.Message, Partials.GuildMember, Partials.User, Partials.Channel] });
  setupEvents(client);
  client.login(getToken()).catch((err) => {
    console.error("[RaidShield] Ã‰chec de connexion mÃªme en mode dÃ©gradÃ©:", err?.message || err);
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
  console.error("[RaidShield] TOKEN manquant â€” dÃ©finis la variable d'environnement TOKEN (ou DISCORD_TOKEN dans .env) puis relance.");
  process.exit(1);
}

// Mode diagnostic (aucune connexion) : valide la sÃ©rialisation des commandes
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
  loginState.error = String(err?.message || err || "");
  console.error("[RaidShield] Échec de connexion:", err?.message || err);
  process.exit(1);
});

setTimeout(() => {
  if (!readyFlag) {
    console.error("[RaidShield] âš ï¸ Aucun signal 'prÃªt' de Discord aprÃ¨s 120s â€” connexion bloquÃ©e.");
  } else {
    console.log("[RaidShield] âœ… Connexion Discord confirmÃ©e.");
  }
}, 120_000);