# Signed by JOE
"""Plain-text field editor.

A full-screen editor for a single configuration field, pushed on top of the
settings page.  It reuses the same header / separator / hint style as every
other page.  Escape cancels; Enter or clicking [Save] saves and returns.
"""

from __future__ import annotations

from pathlib import Path

from textual import on
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, Checkbox, Input, Select, Static, TextArea

from .base import BaseScreen
from .. import schema


class FieldEditScreen(BaseScreen):
    CSS = """
    Screen { layout: vertical; }
    #header { height: auto; }
    #title { text-style: bold; color: $primary; }
    #subtitle { height: auto; color: $text; }
    #status { height: auto; color: $text; }
    #body { height: 1fr; }
    #footer { height: auto; color: $text-muted; }
    #edit-area { height: 1fr; padding: 1 2; }
    #edit-area Input { border: none; background: transparent; }
    #edit-area Input:focus { background: $surface; text-style: bold; }
    #edit-area Select { border: none; background: transparent; }
    #edit-area TextArea { border: none; background: transparent; }
    #edit-area Checkbox { background: transparent; }
    #edit-actions { height: auto; }
    #edit-actions Button { margin-right: 1; border: none; background: transparent; }
    #edit-actions Button:focus { text-style: bold; }
    """

    def __init__(self, app_ref, spec, current_value, on_saved) -> None:
        super().__init__(app_ref)
        self.spec = spec
        self._start_value = current_value
        self.on_saved = on_saved
        self.control = None

    # -- layout ------------------------------------------------------------
    def page_title(self) -> str:
        return f"Edit: {self.spec.label}"

    def page_subtitle(self) -> str:
        return self.spec.help_text or self.spec.description

    def compose(self):
        s = self.spec
        yield Static(self._header_text(), id="header")
        yield Static(self.page_subtitle(), id="subtitle")
        yield Static("", id="status")
        with VerticalScroll(id="edit-area"):
            yield Static(s.label, classes="field-label")
            self.control = self._make_control()
            yield self.control
            yield Static("", id="edit-spacer")
            with Horizontal(id="edit-actions"):
                yield Button("Save", id="btn-save", variant="success")
                yield Button("Cancel", id="btn-cancel", variant="error")
        yield Static("", id="spacer")
        yield Static(self._footer_text(), id="footer")

    def _make_control(self):
        s = self.spec
        if s.type == schema.FieldType.BOOL:
            return Checkbox(
                label=s.label, value=bool(self._start_value), id="edit-control"
            )
        if s.type == schema.FieldType.ENUM:
            current = self._start_value
            if current not in s.choices:
                current = s.choices[0] if s.choices else ""
            return Select(
                [(c, c) for c in s.choices],
                value=current,
                allow_blank=False,
                id="edit-control",
            )
        if s.type == schema.FieldType.STRLIST:
            items = (
                self._start_value
                if isinstance(self._start_value, (list, tuple))
                else []
            )
            return TextArea(
                "\n".join(str(x) for x in items), id="edit-control"
            )
        # STR / INT / FLOAT / SECRET
        secret = bool(s.secret)
        return Input(
            value="" if secret else str(self._start_value or ""),
            password=secret,
            placeholder="******" if secret else "",
            id="edit-control",
        )

    # -- events ------------------------------------------------------------
    def on_mount(self) -> None:
        super().on_mount()
        try:
            self.control.focus()
        except Exception:  # noqa: BLE001
            pass

    def action_back(self) -> None:
        # Escape / Backspace -> cancel the edit.
        self.dismiss(result=False)

    def on_key(self, event) -> None:
        if event.key == "escape":
            event.stop()
            self.dismiss(result=False)
            return
        if event.key == "enter":
            event.stop()
            self._do_save()
            return
        super().on_key(event)

    @on(Input.Submitted, "#edit-control")
    def _input_submitted(self) -> None:
        self._do_save()

    # -- value / save ------------------------------------------------------
    def _control_value(self):
        s = self.spec
        w = self.control
        if s.type == schema.FieldType.BOOL:
            return bool(getattr(w, "value", False))
        if s.type == schema.FieldType.ENUM:
            return w.value
        if s.type == schema.FieldType.STRLIST:
            return getattr(w, "text", "")
        return getattr(w, "value", "")

    def _do_save(self) -> None:
        if getattr(self, "_committing", False):
            return
        self._committing = True
        s = self.spec
        try:
            coerced = schema.coerce_value(s, self._control_value())
        except ValueError as e:
            self.set_status(str(e), level="error")
            self.app.bell()
            self._committing = False
            return
        schema.set_value(self.app_ref.working, s.path, coerced)
        ok, errors, backup = self.app_ref.commit_save()
        if not ok:
            self.set_status("Invalid: " + "; ".join(errors), level="error")
            self.app_ref.bell()
            self._committing = False
            return
        self.app_ref.dirty = False
        if self.on_saved is not None:
            try:
                self.on_saved()
            except Exception:  # noqa: BLE001
                pass
        note = f" (backup: {Path(backup).name})" if backup else ""
        self.set_status(f"Saved.{note}", level="info")
        self.dismiss(result=True)

    @on(Button.Pressed, "#btn-save")
    def _save_pressed(self) -> None:
        self._do_save()

    @on(Button.Pressed, "#btn-cancel")
    def _cancel_pressed(self) -> None:
        self.dismiss(result=False)
