import asyncio
import json
import os
import pathlib
from typing import Callable, Optional

from nicegui import ui

from tg_signer.core import Client, get_api_config, get_proxy, make_dirs


class TelegramLoginDialog:
    """Multi-step Telegram login dialog for WebUI."""

    def __init__(
        self,
        session_dir: str = ".",
        workdir: str = ".signer",
        on_complete: Optional[Callable[[], None]] = None,
    ):
        self.session_dir = pathlib.Path(session_dir)
        self.workdir = pathlib.Path(workdir)
        self.on_complete = on_complete
        self.client: Optional[Client] = None
        self.phone_code_hash: Optional[str] = None
        self.phone_number: Optional[str] = None

        self.dialog = ui.dialog().props("persistent")
        with self.dialog, ui.card().classes("w-full max-w-md"):
            self.header = ui.label("登录 Telegram 账号").classes(
                "text-xl font-bold mb-2"
            )
            self.content = ui.column().classes("w-full gap-3")
            self.status_label = ui.label("").classes("text-sm")

        self._render_phone_step()
        self.dialog.open()

    def _set_status(self, text: str, error: bool = False):
        self.status_label.text = text
        if error:
            self.status_label.classes(replace="text-sm text-red-600")
        else:
            self.status_label.classes(replace="text-sm text-blue-600")

    def _render_phone_step(self):
        self.content.clear()
        with self.content:
            ui.label("请输入手机号，我们将发送验证码到您的 Telegram。").classes(
                "text-gray-600 text-sm"
            )
            self.account_input = ui.input(
                label="账号名称",
                value="my_account",
                placeholder="my_account",
            ).props("outlined dense").classes("w-full")

            self.phone_input = ui.input(
                label="手机号 (含国际区号)",
                placeholder="+8613800138000",
            ).props("outlined dense").classes("w-full")

            with ui.row().classes("w-full justify-end gap-2"):
                ui.button("取消", on_click=self._cancel).props("flat")
                ui.button(
                    "发送验证码", icon="send", on_click=self._send_code
                ).props("color=primary")

    async def _send_code(self):
        phone = (self.phone_input.value or "").strip()
        account = (self.account_input.value or "my_account").strip()

        if not phone:
            self._set_status("请输入手机号", error=True)
            return

        self._set_status("正在连接 Telegram 并发送验证码...")

        try:
            api_id, api_hash = get_api_config()
            proxy = get_proxy()
            self.client = Client(
                account,
                api_id=api_id,
                api_hash=api_hash,
                proxy=proxy,
                workdir=self.session_dir,
                in_memory=True,
            )
            await self.client.connect()

            sent_code = await self.client.send_code(phone)
            self.phone_code_hash = sent_code.phone_code_hash
            self.phone_number = phone

            self._set_status("")
            self._render_code_step()

        except Exception as e:
            self._set_status(f"发送验证码失败: {e}", error=True)

    def _render_code_step(self):
        self.content.clear()
        with self.content:
            ui.label(f"验证码已发送到 {self.phone_number}").classes(
                "text-gray-600 text-sm"
            )
            self.code_input = ui.input(
                label="验证码",
                placeholder="12345",
            ).props("outlined dense").classes("w-full")

            with ui.row().classes("w-full justify-end gap-2"):
                ui.button("取消", on_click=self._cancel).props("flat")
                ui.button(
                    "验证", icon="check", on_click=self._verify_code
                ).props("color=primary")

    async def _verify_code(self):
        code = (self.code_input.value or "").strip()
        if not code:
            self._set_status("请输入验证码", error=True)
            return

        self._set_status("正在验证...")

        try:
            from pyrogram.errors import SessionPasswordNeeded

            await self.client.sign_in(
                self.phone_number,
                self.phone_code_hash,
                code,
            )
            # Login success without 2FA
            await self._on_login_success()

        except SessionPasswordNeeded:
            self._set_status("")
            self._render_2fa_step()

        except Exception as e:
            self._set_status(f"验证失败: {e}", error=True)

    def _render_2fa_step(self):
        self.content.clear()
        with self.content:
            ui.label("此账号已启用两步验证，请输入密码。").classes(
                "text-gray-600 text-sm"
            )
            self.password_input = ui.input(
                label="两步验证密码",
                password=True,
                password_toggle_button=True,
            ).props("outlined dense").classes("w-full")

            with ui.row().classes("w-full justify-end gap-2"):
                ui.button("取消", on_click=self._cancel).props("flat")
                ui.button(
                    "验证密码", icon="lock_open", on_click=self._verify_password
                ).props("color=primary")

    async def _verify_password(self):
        password = (self.password_input.value or "").strip()
        if not password:
            self._set_status("请输入密码", error=True)
            return

        self._set_status("正在验证密码...")

        try:
            await self.client.check_password(password)
            await self._on_login_success()
        except Exception as e:
            self._set_status(f"密码验证失败: {e}", error=True)

    async def _on_login_success(self):
        """Handle successful login: save user info, session, etc."""
        self._set_status("登录成功，正在保存信息...")

        try:
            me = await self.client.get_me()

            # Save me.json
            user_dir = self.workdir / "users" / str(me.id)
            make_dirs(user_dir)

            me_data = {
                "id": me.id,
                "first_name": me.first_name,
                "last_name": me.last_name,
                "username": me.username,
                "phone_number": me.phone_number,
                "is_premium": getattr(me, "is_premium", None),
            }
            with open(user_dir / "me.json", "w", encoding="utf-8") as fp:
                json.dump(me_data, fp, ensure_ascii=False, indent=4)

            # Save latest_chats.json
            latest_chats = []
            try:
                async for dialog in self.client.get_dialogs(20):
                    chat = dialog.chat
                    latest_chats.append(
                        {
                            "id": chat.id,
                            "title": chat.title,
                            "type": str(chat.type) if chat.type else None,
                            "username": chat.username,
                            "first_name": chat.first_name,
                            "last_name": chat.last_name,
                        }
                    )
            except Exception:
                pass  # Non-critical

            if latest_chats:
                with open(
                    user_dir / "latest_chats.json", "w", encoding="utf-8"
                ) as fp:
                    json.dump(latest_chats, fp, ensure_ascii=False, indent=4)

            # Save session_string
            session_string = await self.client.export_session_string()
            ss_file = self.session_dir / (self.client.name + ".session_string")
            with open(ss_file, "w") as fp:
                fp.write(session_string)

            await self.client.disconnect()

            # Trigger file sync if enabled
            try:
                from tg_signer.storage import _file_sync

                if _file_sync:
                    _file_sync.upload()
            except Exception:
                pass

            self._set_status("")
            self._render_success(me_data)

        except Exception as e:
            self._set_status(f"保存信息失败: {e}", error=True)

    def _render_success(self, me_data: dict):
        self.content.clear()
        name = me_data.get("first_name") or ""
        username = me_data.get("username") or ""
        with self.content:
            ui.icon("check_circle", color="green").classes("text-5xl mx-auto")
            ui.label("登录成功!").classes("text-lg font-bold text-center w-full")
            ui.label(
                f"用户: {name} (@{username})" if username else f"用户: {name}"
            ).classes("text-center w-full text-gray-600")
            ui.label(f"ID: {me_data.get('id')}").classes(
                "text-center w-full text-gray-500 text-sm"
            )
            ui.button("完成", on_click=self._finish).classes("w-full mt-2").props(
                "color=primary"
            )

    def _finish(self):
        self.dialog.close()
        if self.on_complete:
            self.on_complete()

    async def _cancel(self):
        if self.client:
            try:
                await self.client.disconnect()
            except Exception:
                pass
        self.dialog.close()
