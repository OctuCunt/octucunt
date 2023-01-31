from typing import Any, Optional

from discord import PartialEmoji
from discord.ext import commands
import discord
import enum

from . import views

BASE_KWARGS: dict[str, Any] = { 
    "content": None, 
    "embeds": [], 
    "attachments": [], 
    "suppress": False, 
    "delete_after": None, 
    "allowed_mentions": None, 
    "view": None, 
}

class _Emojis:
    x = PartialEmoji(name="cross", id=1019436205269602354)
    check = PartialEmoji(name="tick", id=1019436222260723744)
    slash = PartialEmoji(name="slash", id=1041021694682349569)

class CuntContext(commands.Context):
    async def send(self, content: str = None, *args: Any, add_button_view: bool = True, **kwargs: Any):
        embed: Optional[discord.Embed] = kwargs.get("embed")
        if embed is not None:
            if not embed.color:
                embed.color = discord.Color.random()

            if not embed.footer:
                embed.set_footer(
                    text=f"Command ran by {self.author.display_name}",
                    icon_url=self.author.display_avatar,
                )

            if not embed.timestamp:
                embed.timestamp = discord.utils.utcnow()

        if add_button_view:
            if not kwargs.get("view"):
                kwargs["view"] = views.DeleteView(self)
            else:
                _view = kwargs.get("view")
                view = kwargs["view"] = views.DeleteView(self)
                view.add_item(_view.children[0])
        
        if not self.bot.messages.get(self.message):
            self.bot.messages[self.message] = message = (await super().send(content, **kwargs))
            return message
        else:
            message = self.bot.messages.get(self.message)
            edit_kwargs = {key: value for key, value in kwargs.items() if key in BASE_KWARGS}
            edit_kwargs["content"] = content
            edit_kwargs["embeds"] = (kwargs.pop("embeds", [])) or ([kwargs.pop("embed")] if kwargs.get("embed", None) else [])

            try:
                self.bot.messages[self.message] = message = await (self.bot.messages[self.message]).edit(**edit_kwargs)
                return message
            except discord.HTTPException:
                self.bot.messages[self.message] = message = await super().send(content, **kwargs)
                return message

    async def reply(self, *args: Any, mention_author: bool = False, **kwargs: Any):
        return await super().reply(*args, mention_author=mention_author, **kwargs)
    
    Emojis = _Emojis()