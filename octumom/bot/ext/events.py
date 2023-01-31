from discord.ext import commands
import discord

from utils.bot import OctuCunt

class Events(commands.Cog):
    def __init__(self, bot: OctuCunt):
        self.bot = bot

    @commands.Cog.listener()
    async def on_ready(self):
        format = self.bot.format_print("OctuCunt")
        assert self.bot.user

        print(f"{format} | Ready")
        print("|--------------------------------------------------|")
        print(f"Name: OctuCunt")
        print(f"ID: {self.bot.user.id}")
        print(f"Users: {len(self.bot.users)}")
        print(f"Guilds: {len(self.bot.guilds)}")
        print(f"Support Server: {self.bot.support_server}")
        print("|--------------------------------------------------|")


    @commands.Cog.listener()
    async def on_guild_join(self, guild: discord.Guild):
        channel = self.bot.get_log_channel()
        bots = sum(member.bot for member in guild.members)
        embed = discord.Embed(
            title="I joined a new guild!",
            description=f"""
Owner: {guild.owner}
Name: {guild.name}
Members: {guild.member_count}
Bots: {bots}
Nitro Tier: {guild.premium_tier}""",
            color=0x5FAD68,
        )
        await channel.send(embed=embed)


    @commands.Cog.listener()
    async def on_guild_remove(self, guild: discord.Guild):
        channel = self.bot.get_log_channel()
        bots = sum(member.bot for member in guild.members)
        embed = discord.Embed(
            title="I have left a guild",
            description=f"""
Owner: {guild.owner}
Name: {guild.name}
Members: {guild.member_count}
Bots: {bots}
Nitro Tier: {guild.premium_tier}""",
            color=0x5FAD68,
        )
        await channel.send(embed=embed)

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        assert self.bot.user
        if message.content == f"<@{self.bot.user.id}>" and not message.author.bot:
            await message.reply("Hello, I am OctuCunt, my prefix is alone.")

    @commands.Cog.listener("on_message")
    async def afk_check(self, message: discord.Message):
        for mention in message.mentions:
            if mention.id in self.bot.afks and not message.author.bot:
                user = message.guild.get_member(mention.id)
                await message.reply(
                    f"I\'m sorry, but {user.display_name} went afk for {self.bot.afks[mention.id]}.", 
                    mention_author=False
                )

        if message.author.id in self.bot.afks:
            self.bot.afks.pop(message.author.id)
            await self.bot.db.execute("DELETE FROM afk WHERE user_id = $1", message.author.id)

            await message.reply(f"Welcome back {message.author.display_name}!", mention_author=False)
   
    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message, after: discord.Message):
        if not self.bot.messages.get(before):
            return await self.bot.process_commands(after)
        message = self.bot.messages.get(before)
        if not after.content.startswith(await self.bot.get_prefix(before)):
            await message.delete()
            self.bot.messages.pop(before)
        else:
            await self.bot.process_commands(after)
    
    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message):
        if self.bot.messages.get(message):
            bot_message = self.bot.messages.pop(message)
            await bot_message.delete()

async def setup(bot: OctuCunt):
    await bot.add_cog(Events(bot))