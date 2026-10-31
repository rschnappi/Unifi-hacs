"""Entitäten der Dashboard-Formulare (siehe forms.py)."""
from __future__ import annotations

from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.components.select import SelectEntity
from homeassistant.components.sensor import SensorEntity
from homeassistant.components.text import TextEntity
from homeassistant.core import callback

from .coordinator import UniFiCoordinator
from .entity import ControllerEntity
from .forms import NEW, Action, Field, Form


class _FormEntity(ControllerEntity):
    def __init__(self, form: Form, key: str, name: str, icon: str) -> None:
        super().__init__(form.c, f"{form.spec.key}_form_{key}", name)
        self.form = form
        self._attr_icon = icon

    @callback
    def async_entity_id_changed(self, old_entity_id: str) -> None:
        """HA 2026.11+: Entity-ID direkt umbenennen statt entfernen/neu anlegen."""
        if parent := getattr(super(), "async_entity_id_changed", None):
            parent(old_entity_id)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.form.async_add_listener(self.async_write_ha_state))


class FormText(_FormEntity, TextEntity):
    _attr_native_max = 255

    def __init__(self, form: Form, f: Field) -> None:
        super().__init__(form, f.key, f.name, f.icon)
        self._key = f.key

    @property
    def native_value(self) -> str:
        return str(self.form[self._key] or "")

    async def async_set_value(self, value: str) -> None:
        self.form.set(**{self._key: value.strip()})


class FormNumber(_FormEntity, NumberEntity):
    _attr_mode = NumberMode.BOX

    def __init__(self, form: Form, f: Field) -> None:
        super().__init__(form, f.key, f.name, f.icon)
        self._key = f.key
        self._attr_native_min_value = f.minimum
        self._attr_native_max_value = f.maximum
        self._attr_native_step = f.step
        self._attr_native_unit_of_measurement = f.unit

    @property
    def native_value(self) -> float | None:
        val = self.form[self._key]
        return float(val) if val not in (None, "") else None

    async def async_set_native_value(self, value: float) -> None:
        self.form.set(**{self._key: int(value) if float(value).is_integer() else value})


class FormSelect(_FormEntity, SelectEntity):
    def __init__(self, form: Form, f: Field) -> None:
        super().__init__(form, f.key, f.name, f.icon)
        self._key = f.key
        self._opts = f.options

    @property
    def options(self) -> list[str]:
        opts = self._opts(self.coordinator) if callable(self._opts) else list(self._opts or [])
        return opts or ["–"]

    @property
    def current_option(self) -> str | None:
        val = self.form[self._key]
        return val if val in self.options else None

    async def async_select_option(self, option: str) -> None:
        self.form.set(**{self._key: option})


class FormLoader(_FormEntity, SelectEntity):
    """„… laden“: bestehenden Eintrag in die Felder übernehmen oder „Neuer Eintrag“."""

    def __init__(self, form: Form) -> None:
        super().__init__(form, "record", form.spec.loader.name, "mdi:folder-open")

    @property
    def options(self) -> list[str]:
        return [NEW, *self.form.spec.loader.options(self.coordinator)]

    @property
    def current_option(self) -> str:
        cur = self.form.spec.loader.current(self.form)
        return cur if cur in self.options else NEW

    async def async_select_option(self, option: str) -> None:
        self.form.spec.loader.load(self.form, None if option == NEW else option)


class FormButton(_FormEntity, ButtonEntity):
    def __init__(self, form: Form, a: Action) -> None:
        super().__init__(form, a.key, a.name, a.icon)
        self._action = a

    async def async_press(self) -> None:
        await self.form.async_run(self._action)


class FormStatusSensor(ControllerEntity, SensorEntity):
    """Ergebnis der letzten Formular-Aktion (Erfolg oder Fehler)."""

    _attr_icon = "mdi:message-badge"

    def __init__(self, coordinator: UniFiCoordinator) -> None:
        super().__init__(coordinator, "form_status", "Letzte Aktion")

    @callback
    def async_entity_id_changed(self, old_entity_id: str) -> None:
        """HA 2026.11+: Entity-ID direkt umbenennen statt entfernen/neu anlegen."""
        if parent := getattr(super(), "async_entity_id_changed", None):
            parent(old_entity_id)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.coordinator.forms_status.async_add_listener(self.async_write_ha_state))

    @property
    def native_value(self) -> str:
        return self.coordinator.forms_status.message

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        st = self.coordinator.forms_status
        return {"formular": st.form, "erfolgreich": st.ok,
                "zeit": st.time.isoformat() if st.time else None}


def form_entities(coordinator: UniFiCoordinator, platform: str) -> list:
    out: list = []
    for form in coordinator.forms.values():
        spec = form.spec
        if platform == "select" and spec.loader:
            out.append(FormLoader(form))
        for f in spec.fields:
            if f.kind == platform:
                out.append({"text": FormText, "number": FormNumber, "select": FormSelect}[f.kind](form, f))
        if platform == "button":
            out.extend(FormButton(form, a) for a in spec.actions)
    if platform == "sensor":
        out.append(FormStatusSensor(coordinator))
    return out
