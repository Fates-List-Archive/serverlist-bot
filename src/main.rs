#![feature(derive_default_enum)]

use poise::serenity_prelude as serenity;
use log::{debug, info, error};
use std::fs::File;
use std::io::Read;
use std::env;
use std::path::PathBuf;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::process::Command;
use std::time::Duration;
use tokio::{task, time};
use std::sync::Arc;
use poise::serenity_prelude::Mentionable;
use serde_repr::Deserialize_repr;
use serde_repr::Serialize_repr;
use std::borrow::Cow;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

mod helpers;

struct Data {pool: sqlx::PgPool, client: reqwest::Client, key_data: KeyData}
type Error = Box<dyn std::error::Error + Send + Sync>;
type Context<'a> = poise::Context<'a, Data, Error>;

/// Display your or another user's account creation date. Is a test command
#[poise::command(prefix_command, slash_command)]
async fn accage(
    ctx: Context<'_>,
    #[description = "Selected user"] user: Option<serenity::User>,
) -> Result<(), Error> {
    let user = user.as_ref().unwrap_or_else(|| ctx.author());
    ctx.say(format!("{}'s account was created at {}", user.name, user.created_at())).await?;

    Ok(())
}

/// Votes for the current server
#[poise::command(prefix_command, slash_command, track_edits)]
async fn vote(
    ctx: Context<'_>,
) -> Result<(), Error> {
    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to vote").await?;
        return Ok(());
    } 

    let guild = guild.unwrap();

    let data = ctx.data();

    let row = sqlx::query!(
        "SELECT api_token FROM users WHERE user_id = $1",
        ctx.author().id.0 as i64
    )
    .fetch_one(&data.pool)
    .await;

    if row.is_err() {
        ctx.say("You need to login to the site first!").await?;
        return Ok(());
    }

    let token = row.unwrap().api_token;

    let req = data.client.patch(
        format!("https://api.fateslist.xyz/users/{}/servers/{}/votes?test=false", ctx.author().id, guild.id)
    )
    .header("Authorization", token)
    .send()
    .await;

    if req.is_err() {
        ctx.say("Failed to vote for this server. Please try again later.").await?;
        return Ok(());
    }

    let resp = req.unwrap();

    let status = resp.status();

    let json = resp.json::<serde_json::Value>().await?;

    if status == reqwest::StatusCode::OK {
        ctx.send(|m| {
            m.content(format!("You have successfully voted for {}", guild.name)).components(|c| {
                c.create_action_row(|ar| {
                    ar.create_button(|b| {
                        b.style(serenity::ButtonStyle::Primary)
                            .label("Toggle Vote Reminders!")
                            .custom_id(format!("vrtoggle-{}-{}", ctx.author().id, guild.id))
                    })
                })
            })
        }).await?;
    } else {
        ctx.send(|m| {
            m.content(format!("**Error when voting for {}:** {}", guild.name, json["reason"].as_str().unwrap_or("Unknown error"))).components(|c| {
                c.create_action_row(|ar| {
                    ar.create_button(|b| {
                        b.style(serenity::ButtonStyle::Primary)
                            .label("Toggle Vote Reminders!")
                            .custom_id(format!("vrtoggle-{}-{}", ctx.author().id, guild.id))
                    })
                })
            })
        }).await?;
    }

    Ok(())
}

async fn autocomplete_vr(
    ctx: Context<'_>,
    _partial: String
) -> Vec<poise::AutocompleteChoice<String>> {
    let data = ctx.data();

    let row = sqlx::query!(
        "SELECT vote_reminders_servers FROM users WHERE user_id = $1",
        ctx.author().id.0 as i64
        )
        .fetch_one(&data.pool)
        .await;

    if row.is_err() {
        return Vec::new();
    }

    let row = row.unwrap();

    let mut choices = Vec::new();
    for choice in row.vote_reminders_servers {
        choices.push(poise::AutocompleteChoice {
            name: choice.to_string(),
            value: choice.to_string(),
        });
    }

    choices
}

/// Disable vote reminders for a bot
#[poise::command(
    prefix_command, 
    track_edits, 
    slash_command
)]
async fn disablevr(
    ctx: Context<'_>,
    #[description = "Server ID to disable vote reminders for"]
    #[autocomplete = "autocomplete_vr"]
    server_id: Option<String>,
)  -> Result<(), Error> {

    let data = ctx.data();

    if server_id.is_none() {
        let row = sqlx::query!(
            "SELECT vote_reminders_servers FROM users WHERE user_id = $1",
            ctx.author().id.0 as i64
            )
            .fetch_one(&data.pool)
            .await;

        
        let mut text = "Vote reminders enabled: ".to_string();

        for choice in row.unwrap().vote_reminders_servers {
            text += &(choice.to_string() + ", ");
        }
    
        ctx.say(text).await?;
    } else {
        let server_id = server_id.unwrap();

        let server_id = server_id.parse::<i64>();

        if server_id.is_err() {
            ctx.say("Server id must be a i64").await?;
            return Ok(());
        }

        let server_id = server_id.unwrap();

        sqlx::query!(
            "UPDATE users SET vote_reminders_servers = array_remove(vote_reminders_servers, $1) WHERE user_id = $2",
            server_id,
            ctx.author().id.0 as i64
        )
        .execute(&data.pool)
        .await?;

        ctx.say(format!("Vote reminders disabled for {}", server_id)).await?;
    }

    Ok(())
}

/// Tag base command
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "SEND_MESSAGES")]
async fn tags(
    ctx: Context<'_>,
) -> Result<(), Error> {
    ctx.say("Available options are ``tags add``, ``tags dump``, ``tags remove``, ``tags edit``, ``tags nuke`` and ``tags transfer``.").await?;
    Ok(())
}

/// Adds a tag
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "MANAGE_GUILD", rename = "add")]
async fn tag_add(
    ctx: Context<'_>,
    #[description = "Tag name"]
    tag_name: String
) -> Result<(), Error> {
    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let sanitized = tag_name.chars().filter(|&c| c.is_alphabetic() || c == ' ').collect::<String>();

    if sanitized != tag_name {
        ctx.say("Tag name contains invalid characters. Only a-z and spaces are allowed.").await?;
        return Ok(());
    }

    let banned = vec!["best-", "good-", "fuck", "nigger", "fates-list", "fateslist"];

    for kw in banned {
        if tag_name.contains(kw) {
            ctx.say(&format!("{} not allowed in tag names", kw)).await?;
            return Ok(())
        }
    }

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            sqlx::query!(
                "INSERT INTO server_tags (id, name, iconify_data, owner_guild) VALUES ($1, $2, $3, $4)",
                internal_tag_name,
                tag_name,
                "fluent:animal-cat-28-regular",
                guild.id.0 as i64,
            )
            .execute(&data.pool)
            .await?;

            // Then just update tags array
            sqlx::query!(
                "UPDATE servers SET tags = array_append(tags, $1) WHERE guild_id = $2",
                internal_tag_name,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            ctx.say(format!("Tag {} added and ownership claimed as this is a brand new tag!", tag_name)).await?;
        },
        Err(e) => {
            ctx.say(format!("Error: {}", e)).await?;
        },
        Ok(row) => {
            // Check if tag already exists
            let check = sqlx::query!(
                "SELECT tags FROM servers WHERE guild_id = $1",
                guild.id.0 as i64
            )
            .fetch_one(&data.pool)
            .await?;

            for tag in check.tags.unwrap_or_default() {
                if tag == internal_tag_name {
                    ctx.say(format!("Tag {} is already present on this server!", tag_name)).await?;
                    return Ok(());
                }
            }

            // Then just update tags array
            sqlx::query!(
                "UPDATE servers SET tags = array_append(tags, $1) WHERE guild_id = $2",
                internal_tag_name,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            let mut owner_guild = row.owner_guild;

            if owner_guild == 0 {
                // We have a unclaimed tag, claim it
                sqlx::query!(
                    "UPDATE server_tags SET owner_guild = $1 WHERE id = $2",
                    guild.id.0 as i64,
                    internal_tag_name
                )
                .execute(&data.pool)
                .await?;
                owner_guild = guild.id.0 as i64;
            }

            ctx.say(format!("Tag {} added. The current owner server of this tag is {}. You can get detailed tag information using ``tag dump``!", tag_name, owner_guild)).await?;
        }
    }

    Ok(())
}

/// Edits a tag
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "MANAGE_GUILD", rename = "edit")]
async fn tag_edit(
    ctx: Context<'_>,
    #[description = "Tag name"]
    tag_name: String,
    #[description = "New iconify icon (see https://iconify.design)"]
    iconify_data: String
) -> Result<(), Error> {

    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            ctx.say(format!("Tag {} not found", tag_name)).await?;
        },
        Err(e) => {
            ctx.say(format!("Error: {}", e)).await?;
        },
        Ok(row) => {
            if row.owner_guild != guild.id.0 as i64 {
                ctx.say(format!("You do not own tag {} and as such you may not modify its properties.\n\nContact Fates List Staff if you think this server is holding the tag for malicious purposes and does not allow for sane discussion over it.", tag_name)).await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE server_tags SET iconify_data = $1 WHERE id = $2",
                iconify_data,
                internal_tag_name
            )
            .execute(&data.pool)
            .await?;

            ctx.say(format!("Tag {} updated!", tag_name)).await?;
        }
    }

    Ok(())
}

/// Nukes a tag if it is only present in one or less servers
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "MANAGE_GUILD", rename = "nuke")]
async fn tag_nuke(
    ctx: Context<'_>,
    #[description = "Tag name"]
    tag_name: String,
) -> Result<(), Error> {

    let data = ctx.data();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT guild_id FROM servers WHERE tags && $1",
        &vec![internal_tag_name.clone()]
    )
    .fetch_all(&data.pool)
    .await?;

    if check.len() > 1 {
        ctx.say(format!("Tag {} is present on more than one server and cannot be nuked: {:?}.", tag_name, check)).await?;
        return Ok(());
    }

    sqlx::query!(
        "DELETE FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .execute(&data.pool)
    .await?;

    sqlx::query!(
        "UPDATE servers SET tags = array_remove(tags, $1)",
        internal_tag_name
    )
    .execute(&data.pool)
    .await?;

    ctx.say("Tag nuked!").await?;

    Ok(())
}

/// Transfers a tag
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "MANAGE_GUILD", rename = "transfer")]
async fn tag_transfer(
    ctx: Context<'_>,
    #[description = "Tag name"]
    tag_name: String,
    #[description = "New server. Set to 'unclaim' to unclaim the tag. A unclaimed tag may be claimed by adding it."]
    new_server: String
) -> Result<(), Error> {

    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            ctx.say(format!("Tag {} not found", tag_name)).await?;
        },
        Err(e) => {
            ctx.say(format!("Error: {}", e)).await?;
        },
        Ok(row) => {
            if row.owner_guild != guild.id.0 as i64 {
                ctx.say(format!("You do not own tag {} and as such you may not modify its properties.\n\nContact Fates List Staff if you think this server is holding the tag for malicious purposes and does not allow for sane discussion over it.", tag_name)).await?;
                return Ok(());
            }

            if new_server == "unclaim" {
                // Remove tag claim
                sqlx::query!(
                    "UPDATE server_tags SET owner_guild = $1 WHERE id = $2",
                    0,
                    internal_tag_name
                )
                .execute(&data.pool)
                .await?;

                ctx.say(format!("Tag {} unclaimed!", tag_name)).await?;

                return Ok(())
            }

            let new_server_id = match new_server.parse::<i64>() {
                Ok(id) => id,
                Err(_) => {
                    ctx.say(format!("Server {} is not a i64", new_server)).await?;
                    return Ok(());
                }
            };

            let check = sqlx::query!(
                "SELECT tags FROM servers WHERE guild_id = $1",
                new_server_id
            )
            .fetch_one(&data.pool)
            .await?;

            for tag in check.tags.unwrap_or_default() {
                if tag == internal_tag_name {
                    sqlx::query!(
                        "UPDATE server_tags SET owner_guild = $1 WHERE id = $2",
                        new_server_id,
                        internal_tag_name
                    )
                    .execute(&data.pool)
                    .await?;

                    ctx.say(format!("Tag {} transferred!", tag_name)).await?;
                    return Ok(());
                }
            }
            ctx.say(format!("Tag {} could not be transferred as recipient server does not also have tag!", tag_name)).await?;
        }
    }

    Ok(())
}

/// Dumps a tag
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "SEND_MESSAGES", rename = "dump")]
async fn tag_dump(
    ctx: Context<'_>,
    #[description = "Tag name or internal name"]
    tag_name: String
) -> Result<(), Error> {
    let data = ctx.data();

    // Dump tag table
    let row = sqlx::query!(
        "SELECT to_json(server_tags) AS json FROM server_tags WHERE id = $1 OR name = $1",
        tag_name
    )
    .fetch_one(&data.pool)
    .await?;

    let data = serde_json::to_string_pretty(&row.json)?;

    // Get around attachment limitation
    ctx.defer().await?;

    ctx.send(|m| {
        m.content("Tag dump");
        m.attachment(serenity::AttachmentType::Bytes { data: Cow::from(data.as_bytes().to_vec()), filename: "tag-dump.json".to_string() } )
    }).await?;

    Ok(())
}

/// Removes a tag from a server.
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "MANAGE_GUILD", rename = "remove")]
async fn tag_remove(
    ctx: Context<'_>,
    #[description = "Tag name"]
    tag_name: String
) -> Result<(), Error> {
    let data = ctx.data();

    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    let internal_tag_name = tag_name.replace(' ', "-").to_lowercase();

    let check = sqlx::query!(
        "SELECT owner_guild FROM server_tags WHERE id = $1",
        internal_tag_name
    )
    .fetch_one(&data.pool)
    .await;

    match check {
        Err(sqlx::Error::RowNotFound) => {
            ctx.say(format!("Tag {} not found", tag_name)).await?;
        },
        Err(e) => {
            ctx.say(format!("Error: {}", e)).await?;
        },
        Ok(row) => {
            if row.owner_guild == guild.id.0 as i64 {
                ctx.say(format!("You currently own tag {} and as such cannot remove it. Consider transferring it to another server using ``tag transfer``. See ``help`` for more information.", tag_name)).await?;
                return Ok(());
            }

            // Then just update tags array
            sqlx::query!(
                "UPDATE servers SET tags = array_remove(tags, $1) WHERE guild_id = $2",
                internal_tag_name,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;

            ctx.say(format!("Tag {} removed if present. You can use ``dumpserver`` to verify this", tag_name)).await?;
        }
    }

    Ok(())
}


/// View audit logs.
#[poise::command(prefix_command, slash_command, guild_cooldown = 10, required_permissions = "SEND_MESSAGES")]
async fn auditlogs(
    ctx: Context<'_>,
) -> Result<(), Error> {
    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let guild = guild.unwrap();

    // Get around attachment limitation
    ctx.defer().await?;

    // Dump server table
    let row = sqlx::query!(
        "SELECT to_json(server_audit_logs) AS json FROM server_audit_logs WHERE guild_id = $1",
        guild.id.0 as i64
    )
    .fetch_all(&ctx.data().pool)
    .await?;

    let logs = Vec::from_iter(row.iter().map(|row| row.json.as_ref().unwrap()));

    let data = serde_json::to_string_pretty(&logs)?;

    ctx.send(|m| {
        m.content("Audit Logs");
        m.attachment(serenity::AttachmentType::Bytes { data: Cow::from(data.as_bytes().to_vec()), filename: "audit-logs.json".to_string() } )
    }).await?;

    Ok(())
}

/// Dumps the server data to a file for viewing.
#[poise::command(prefix_command, track_edits, slash_command, guild_cooldown = 10, required_permissions = "ADMINISTRATOR")]
async fn dumpserver(
    ctx: Context<'_>,
) -> Result<(), Error> {
    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let member = ctx.author_member().await.unwrap();

    let guild = guild.unwrap();

    // Dump server table
    let row = sqlx::query!(
        "SELECT to_json(servers) AS json FROM servers WHERE guild_id = $1",
        guild.id.0 as i64
    )
    .fetch_one(&ctx.data().pool)
    .await?;

    let data = serde_json::to_string_pretty(&row.json.unwrap_or_else(|| serde_json::json!({})))?;

    member.user.create_dm_channel(&ctx.discord()).await?.send_message(&ctx.discord(),|m| {
        m.content("JSON requested");
        m.files(vec![serenity::AttachmentType::Bytes { data: Cow::from(data.as_bytes().to_vec()), filename: "server-dump.json".to_string() }] )
    }).await?;

    ctx.say("DMed you server dump").await?;

    Ok(())
}



#[derive(poise::ChoiceParameter, Debug)]
enum SetField {
    #[name = "Description"] Description,
    #[name = "Long Description"] LongDescription,
    #[name = "Long Description Type"] LongDescriptionType,
    #[name = "Invite Code"] InviteCode,
    #[name = "Invite Channel ID"] InviteChannelID, 
    #[name = "Website"] Website, 
    #[name = "CSS"] Css, 
    #[name = "Banner (server card)"] BannerCard,
    #[name = "Banner (server page)"] BannerPage, 
    #[name = "Keep Banner Decorations"] KeepBannerDecor, // Done till here
    #[name = "Vanity"] Vanity,
    #[name = "Webhook URL"] WebhookURL,
    #[name = "Webhook Secret"] WebhookSecret,
    #[name = "Webhook HMAC Only"] WebhookHMACOnly,
    #[name = "Requires Login To Join"] RequiresLogin,
    #[name = "Vote Roles"] VoteRoles,
    #[name = "Whitelist Only"] WhitlistOnly,
    #[name = "Whitelist Form"] WhitelistForm,
}

#[derive(Eq, Serialize_repr, Deserialize_repr, PartialEq, Clone, Copy, Default)]
#[repr(i32)]
enum LongDescriptionType {
    Html = 0,
    #[default]
    MarkdownServerSide = 1,
}

fn create_token(length: usize) -> String {
    thread_rng()
    .sample_iter(&Alphanumeric)
    .take(length)
    .map(char::from)
    .collect()
}

/// Sets a field
#[poise::command(prefix_command, track_edits, slash_command, guild_cooldown = 5, required_permissions = "MANAGE_GUILD")]
async fn set(
    ctx: Context<'_>,
    #[description = "Field to set"]
    field: SetField,
    #[description = "(Raw) Value to set field to. 'none' to reset"]
    value: String,
) -> Result<(), Error> {
    let guild = ctx.guild();

    if guild.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let member = ctx.author_member().await;

    if member.is_none() {
        ctx.say("You must be in a server to use this command").await?;
        return Ok(());
    }

    let mut value = value; // Force it to be mutable and shadow immutable value

    if value == "none".to_string() {
        value = "".to_string();
    }

    let guild = guild.unwrap();    

    let data = ctx.data();

    // Update server details
    sqlx::query!(
        "INSERT INTO servers (guild_id, owner_id, name_cached, avatar_cached, api_token, guild_count) VALUES ($1, $2, $3, $4, $5, $6) 
        ON CONFLICT (guild_id) DO UPDATE SET owner_id = excluded.owner_id, name_cached = excluded.name_cached, 
        avatar_cached = excluded.avatar_cached, guild_count = excluded.guild_count WHERE servers.guild_id = $1",
        guild.id.0 as i64,
        ctx.author().id.0 as i64,
        guild.name.to_string(),
        guild.icon_url().unwrap_or_else(|| "https://api.fateslist.xyz/static/botlisticon.webp".to_string()),
        create_token(128),
        guild.member_count as i64
    )
    .execute(&data.pool)
    .await?;

    let member = member.unwrap();

    // Force HTTP(s)
    value = value.replace("http://", "https://");

    // Handle pastebin
    if value.starts_with("https://pastebin.com/") || value.starts_with("https://www.pastebin.com") || value.starts_with("pastebin.com") {
        value = value.replacen("pastebin.com/", "pastebin.com/raw/", 1);
        let res = data.client.get(&value)
        .send()
        .await?;

        let status = res.status();

        if status.is_success() {
            value = res.text().await?;
        } else {
            ctx.say("Error: Could not get pastebin due to status code: ".to_string()+status.as_str()).await?;
            return Ok(());
        }
    }

    match field {
        SetField::Description => {
            if value.len() > 200 {
                ctx.say("Description must be less than 200 characters").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET description = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::LongDescription => {
            if value.len() < 200 {
                ctx.say("Long description must be at least 200 characters.\n\nThis is required in order to create a optimal user experience for your users!\n\nHINT: Pastebin links are supported too!").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET long_description = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::LongDescriptionType => {
            let long_desc_type = match value.as_str() {
                "html" | "0" => LongDescriptionType::Html,
                "markdown" | "1" => LongDescriptionType::MarkdownServerSide,
                _ => {
                    ctx.say("Long description type must be either `html` (`0`) or `markdown` (`1`)").await?;
                    return Ok(());
                }
            };

            sqlx::query!(
                "UPDATE servers SET long_description_type = $1 WHERE guild_id = $2",
                long_desc_type as i32,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::InviteCode => {
            // Check for MANAGE_GUILD
            let bot = ctx.discord().cache.current_user();
            let bot_member = guild.member(&ctx.discord(), bot.id).await?;
            if !bot_member.permissions(&ctx.discord())?.manage_guild() {
                ctx.say("The bot must have the `Manage Server` permission to change invite codes.
This is due to a dumb discord API decision to lock some *basic* invite information behind Manage Server
                
It is strongly recommended to remove this permission **immediately** after setting invite code for security purposes"
            ).await?;
                return Ok(());
            }

            // Validate invite code
            let guild_invites = guild.invites(&ctx.discord()).await?;

            value = value.replace("https://discord.gg/", "").replace("https://discord.com/invite/", "");

            let mut got_invite: Option<serenity::RichInvite> = None;
            for invite in guild_invites {
                if invite.code == value {
                    got_invite = Some(invite);
                    break;
                }
            }

            if got_invite.is_none() {
                ctx.say("Invite code could not be found on this guild").await?;
                return Ok(());
            }

            let got_invite = got_invite.unwrap();

            if got_invite.max_age != 0 {
                ctx.say("Invite code must be permanent/unlimited time. 
                
This is required to provide our users with the optimal experience and not tons of broken links.").await?;
                return Ok(());
            }

            if got_invite.max_uses != 0 {
                ctx.say("Invite code must be unlimited use. 
                
This is required to provide our users with the optimal experience and not tons of broken links.").await?;
                return Ok(());
            }

            if got_invite.temporary {
                ctx.say("Invite code must not be temporary. 
                
This is required to provide our users with the optimal experience and not tons of broken links.").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET invite_url = $1 WHERE guild_id = $2",
                got_invite.code,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::InviteChannelID => {
            // Check for CREATE_INVITES
            let value: String = value.chars().filter(|c| c.is_digit(10)).collect();

            let value_i64 = value.parse::<i64>()?;

            let bot = ctx.discord().cache.current_user();

            let mut got_channel: Option<serenity::GuildChannel> = None;

            for channel in guild.channels(&ctx.discord()).await? {
                if channel.0.0 == value_i64 as u64 {
                    got_channel = Some(channel.1);
                }
            }

            if got_channel.is_none() {
                ctx.say("Channel could not be found on this guild").await?;
                return Ok(());
            }

            let got_channel = got_channel.unwrap();

            if! got_channel.permissions_for_user(&ctx.discord(), bot.id)?.create_invite() {
                ctx.say("The bot must have the `Create Instant Invite` permission to set invite channel.").await?;
                return Ok(())
            }

            sqlx::query!(
                "UPDATE servers SET invite_channel = $1 WHERE guild_id = $2",
                value_i64,
                guild.id.0 as i64
            )
            .execute(&data.pool)
            .await?;            
        },
        SetField::Website => {
            if !value.starts_with("https://") && value != "".to_string() {
                ctx.say("Website must start with https://").await?;
                return Ok(());
            }

            sqlx::query!(
                "UPDATE servers SET website = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::Css => {
            sqlx::query!(
                "UPDATE servers SET css = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::BannerCard => {
            ctx.defer().await?;
            helpers::check_banner_img(&data.client, &value).await?;

            sqlx::query!(
                "UPDATE servers SET banner_card = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::BannerPage => {
            ctx.defer().await?;
            helpers::check_banner_img(&data.client, &value).await?;

            sqlx::query!(
                "UPDATE servers SET banner_page = $1 WHERE guild_id = $2",
                value,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        SetField::KeepBannerDecor => {
            let keep_banner_decor = match value.as_str() {
                "true" | "0" => true,
                "false" | "1" => false,
                _ => {
                    ctx.say("keep_banner_decor must be either `false` (`0`) or `true` (`1`)").await?;
                    return Ok(());
                }
            };

            sqlx::query!(
                "UPDATE servers SET keep_banner_decor = $1 WHERE guild_id = $2",
                keep_banner_decor,
                ctx.guild().unwrap().id.0 as i64
            )
            .execute(&data.pool)
            .await?;
        },
        _ => {
            ctx.say("This command is being revamped right now and this option is not currently available!").await?;
        }
    }

    // Audit log entry

    sqlx::query!(
        "INSERT INTO server_audit_logs (guild_id, user_id, username, user_guild_perms, field, value) VALUES ($1, $2, $3, $4, $5, $6)",
        guild.id.0 as i64,
        ctx.author().id.0 as i64,
        ctx.author().name,
        member.permissions(&ctx.discord()).unwrap().bits().to_string(),
        format!("{:?}", field),
        value
    )
    .execute(&data.pool)
    .await?;


    ctx.say(format!("Set {:?} successfully. Either use /dumpserver or check out your server page!", field)).await?;

    Ok(())
}

/// Show this help menu
#[poise::command(prefix_command, track_edits, slash_command)]
async fn help(
    ctx: Context<'_>,
    #[description = "Specific command to show help about"]
    #[autocomplete = "poise::builtins::autocomplete_command"]
    command: Option<String>,
) -> Result<(), Error> {
    poise::builtins::help(
        ctx,
        command.as_deref(),
        poise::builtins::HelpConfiguration {
            extra_text_at_bottom: "\
Server Listing Help. Ask on our support server for more information\n",
            show_context_menu_commands: true,
            ..poise::builtins::HelpConfiguration::default()
        },
    )
    .await?;
    Ok(())
}

/// Returns version information
#[poise::command(prefix_command, slash_command)]
async fn about(ctx: Context<'_>) -> Result<(), Error> {
    let git_commit_hash = Command::new("git")
    .args(["rev-parse", "HEAD"]).output();


    let hash = if git_commit_hash.is_err() {
        "Unknown".to_string()
    } else {
        String::from_utf8(git_commit_hash.unwrap().stdout).unwrap_or_else(|_| "Unknown (utf8 parse failure)".to_string())
    };

    ctx.say(format!("Server Listing v0.1.0\n\n**Commit Hash:** {}", hash)).await?;
    Ok(())
}

/// Register application commands in this guild or globally
///
/// Run with no arguments to register in guild, run with argument "global" to register globally.
#[poise::command(prefix_command, hide_in_help, owners_only, track_edits)]
async fn register(ctx: Context<'_>, #[flag] global: bool) -> Result<(), Error> {
    poise::builtins::register_application_commands(ctx, global).await?;

    Ok(())
}

#[derive(Deserialize, Clone)]
pub struct KeyChannels {
    vote_reminder_channel: serenity::model::id::ChannelId,
}

#[derive(Deserialize, Clone)]
pub struct KeyData {
    channels: KeyChannels,
}

fn get_data_dir() -> String {
    let path = match env::var_os("HOME") {
        None => { panic!("$HOME not set"); }
        Some(path) => PathBuf::from(path),
    };    

    let data_dir = path.into_os_string().into_string().unwrap() + "/FatesList/config/data/";

    debug!("Data dir: {}", data_dir);

    data_dir
}

fn get_key_data() -> KeyData {
    let data_dir = get_data_dir();

    // open discord.json, handle config
    let mut file = File::open(data_dir + "discord.json").expect("No config file found");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let data: KeyData = serde_json::from_str(&data).expect("Discord JSON was not well-formatted");

    data
}

#[derive(Deserialize)]
struct Secrets {
    token_server: String
}

fn get_bot_token() -> String {
    let data_dir = get_data_dir();

    // open secrets.json, handle config
    let mut file = File::open(data_dir + "secrets.json").expect("No config file found");
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    let secrets: Secrets = serde_json::from_str(&data).expect("JSON was not well-formatted");

    secrets.token_server
}

async fn on_error(error: poise::FrameworkError<'_, Data, Error>) {
    // This is our custom error handler
    // They are many errors that can occur, so we only handle the ones we want to customize
    // and forward the rest to the default handler
    match error {
        poise::FrameworkError::Setup { error } => panic!("Failed to start bot: {:?}", error),
        poise::FrameworkError::Command { error, ctx } => {
            error!("Error in command `{}`: {:?}", ctx.command().name, error,);
            ctx.say(format!("There was an error running this command: {:?}", error)).await.unwrap();
        }
        error => {
            if let Err(e) = poise::builtins::on_error(error).await {
                error!("Error while handling error: {}", e);
            }
        }
    }
}

async fn event_listener(
    ctx: &serenity::Context,
    event: &poise::Event<'_>,
    _framework: &poise::Framework<Data, Error>,
    user_data: &Data,
) -> Result<(), Error> {
    match event {
        poise::Event::Ready { data_about_bot } => {
            info!("{} is connected!", data_about_bot.user.name);

            let ctx = ctx.to_owned();
            let pool = user_data.pool.clone();
            let key_data = user_data.key_data.clone();

            task::spawn(async move {
                vote_reminder_task(pool, key_data, ctx.http).await;
            });
        }
        poise::Event::InteractionCreate { interaction } => {
            let msg_inter = interaction.clone().message_component();
            if msg_inter.is_some() {
                let msg_inter = msg_inter.unwrap();
                // Now get the custom id
                let custom_id = msg_inter.data.custom_id.clone();
                if custom_id.starts_with("vrtoggle-") {
                    let parts: Vec<&str> = custom_id.split('-').collect();
                    if parts.len() != 3 {
                        return Ok(());
                    }
                    let user_id = parts[1].parse::<i64>();
                    let server_id = parts[2].parse::<i64>();
                    if user_id.is_ok() && server_id.is_ok() {
                        let user_id = user_id.unwrap();
                        let server_id = server_id.unwrap();
                    
                        let author = msg_inter.user.id.0 as i64;

                        if user_id != author {
                            return Ok(());
                        }

                        // Check if they've signed up for VR already
                        let row = sqlx::query!(
                            "SELECT vote_reminders_servers FROM users WHERE user_id = $1",
                            user_id
                        )
                        .fetch_one(&user_data.pool)
                        .await;
                        
                        match row.as_ref().err() {
                            Some(sqlx::Error::RowNotFound) => {
                                debug!("Choosing VR path RowInsert");
                                sqlx::query!(
                                    "INSERT INTO users (user_id, vote_reminders_servers) VALUES ($1, $2)",
                                    user_id,
                                    &vec![server_id]
                                )
                                .execute(&user_data.pool)
                                .await?;
                                msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                    m.interaction_response_data(|m| {
                                        m.content("You have successfully subscribed to vote reminders!");
                                        m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);

                                        m
                                    })
                                }).await?;
                            },
                            None => {
                                debug!("Choosing VR path RowUpdate");
                                
                                let row = row.unwrap();
                                for server in row.vote_reminders_servers {
                                    if server == server_id {
                                        msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                            m.interaction_response_data(|m| {
                                                m.content("You have already subscribed to vote reminders for this server!");
                                                m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);
        
                                                m
                                            })
                                        }).await?; 
                                        return Ok(());       
                                    }
                                }

                                sqlx::query!(
                                    "UPDATE users SET vote_reminders_servers = vote_reminders_servers || $2 WHERE user_id = $1",
                                    user_id,
                                    &vec![server_id]
                                )
                                .execute(&user_data.pool)
                                .await?;
                                msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                    m.interaction_response_data(|m| {
                                        m.content("You have successfully subscribed to vote reminders!");
                                        m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);

                                        m
                                    })
                                }).await?;
                            },
                            Some(err) => {
                                // Odd error, lets return it
                                error!("{}", err);
                                msg_inter.create_interaction_response(ctx.http.clone(), |m| {
                                    m.interaction_response_data(|m| {
                                        m.content(format!("**Error:** {}", err));
                                        m.flags(serenity::model::interactions::InteractionApplicationCommandCallbackDataFlags::EPHEMERAL);

                                        m
                                    })
                                }).await?;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

async fn vote_reminder_task(pool: sqlx::PgPool, key_data: KeyData, http: Arc<serenity::http::Http>) {
    let mut interval = time::interval(Duration::from_millis(10000));

    loop {
        interval.tick().await;
        debug!("Called VRTask"); // TODO: Remove this

        let rows = sqlx::query!(
            "SELECT user_id, vote_reminders_servers, vote_reminder_channel FROM users 
            WHERE cardinality(vote_reminders_servers) > 0 
            AND NOW() - vote_reminders_servers_last_acked > interval '4 hours'"
        )
        .fetch_all(&pool)
        .await;

        if rows.is_err() {
            error!("{}", rows.err().unwrap());
            continue;
        }

        let rows = rows.unwrap();

        for row in rows {
            // If a user can't vote for one bot, they can't vote for any
            let count = sqlx::query!(
                "SELECT COUNT(1) FROM user_server_vote_table WHERE user_id = $1",
                row.user_id
            )
            .fetch_one(&pool)
            .await;

            if count.is_err() || count.unwrap().count.unwrap_or_default() > 0 {
                continue
            }

            let mut channel: serenity::model::id::ChannelId = key_data.channels.vote_reminder_channel;
            if row.vote_reminder_channel.is_some() {
                channel = serenity::model::id::ChannelId(row.vote_reminder_channel.unwrap().try_into().unwrap_or(key_data.channels.vote_reminder_channel.0));
            }

            // The hard part, bot string creation

            let mut servers_str: String = "".to_string();

            // tlen contains the total length of the vote reminders
            // If tlen is one and was always one then we don't need to add a comma
            let tlen_initial = row.vote_reminders_servers.len();
            let mut tlen = row.vote_reminders_servers.len();

            for server in &row.vote_reminders_servers {
                let mut mod_front = "";
                if tlen_initial > 1 && tlen == 1 {
                    // We have more than one bot, but we're at the last one
                    mod_front = " and ";
                } else if tlen_initial > 1 && tlen > 1 {
                    // We have more than one bot, and we're not at the last one
                    mod_front = ", ";
                }

                servers_str += format!("the server {mod_front} {server}", server = server, mod_front = mod_front).as_str();

                tlen -= 1;
            }

            // Now actually send the message
            let res = channel.send_message(http.clone(), |m| {

                m.content(
                    format!(
                        "Hey {user}, you can vote for {servers} or did you forget?",
                        user = serenity::model::id::UserId(row.user_id as u64).mention(),
                        servers = servers_str
                    ));

                m
            })
            .await;

            if res.is_err() {
                error!("Message send error: {}", res.err().unwrap());
            }

            debug!("User {} with servers {:?}", row.user_id, row.vote_reminders_servers);

            // Reack
            let reack = sqlx::query!(
                "UPDATE users SET vote_reminders_servers_last_acked = NOW() WHERE user_id = $1",
                row.user_id
            )
            .execute(&pool)
            .await;

            if reack.is_err() {
                error!("Reack error: {}", reack.err().unwrap());
            }
        }
    }
}

#[tokio::main]
async fn main() {
    const MAX_CONNECTIONS: u32 = 3; // max connections to the database, we don't need too many here

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "serverlist_bot=debug");
    }
    env_logger::init();
    info!("Starting Server Listing...");

    let client = reqwest::Client::builder()
    .user_agent("FatesList-ServerList/1.0 (internal microservice)")
    .build()
    .unwrap();

    let err = poise::Framework::build()
        .token(get_bot_token())
        .user_data_setup(move |_ctx, _ready, _framework| Box::pin(async move {
            Ok(Data {
                pool: PgPoolOptions::new()
                .max_connections(MAX_CONNECTIONS)
                .connect("postgres://localhost/fateslist")
                .await
                .expect("Could not initialize connection"),
                key_data: get_key_data(),
                client,
            })
        }))
        .client_settings(|c| {
            // This is *for now*
            c.intents(serenity::GatewayIntents::GUILDS | serenity::GatewayIntents::MESSAGE_CONTENT | serenity::GatewayIntents::GUILD_MESSAGES | serenity::GatewayIntents::DIRECT_MESSAGES | serenity::GatewayIntents::GUILD_MEMBERS | serenity::GatewayIntents::GUILD_PRESENCES)
        })
        .options(poise::FrameworkOptions {
            // configure framework here
            prefix_options: poise::PrefixFrameworkOptions {
                prefix: Some("~".into()),
                ..poise::PrefixFrameworkOptions::default()
            },
            /// This code is run before every command
            pre_command: |ctx| {
                Box::pin(async move {
                    info!("Executing command {} for user {} ({})...", ctx.command().qualified_name, ctx.author().name, ctx.author().id);
                })
            },
            /// This code is run after every command returns Ok
            post_command: |ctx| {
                Box::pin(async move {
                    info!("Done executing command {} for user {} ({})...", ctx.command().qualified_name, ctx.author().name, ctx.author().id);
                })
            },
            on_error: |error| Box::pin(on_error(error)),
            listener: |ctx, event, framework, user_data| { 
                Box::pin(event_listener(ctx, event, framework, user_data))
            },
            commands: vec![
                accage(), 
                vote(), 
                help(), 
                register(), 
                about(), 
                disablevr(), 
                set(), 
                dumpserver(), 
                auditlogs(),
                poise::Command {
                    subcommands: vec![
                        tag_add(),
                        tag_edit(),
                        tag_remove(),
                        tag_transfer(),
                        tag_nuke(),
                        tag_dump()
                    ],
                    ..tags()
                }
            ],
            ..poise::FrameworkOptions::default()
        })
        .run().await;

        if err.is_err() {
            error!("{}", err.err().unwrap());
        }
}
