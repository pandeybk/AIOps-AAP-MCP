import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx
import urllib3
import yaml
try:
    from kafka import KafkaConsumer
except ModuleNotFoundError:  # pragma: no cover - handled at runtime in container
    KafkaConsumer = None


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger("playbook_bridge")
TERMINAL_JOB_STATES = {"successful", "failed", "error", "canceled"}
INCIDENT_ID_PATTERN = re.compile(r"/incidents/([^/]+)/playbook-generation/callback")
CALLBACK_URL_PATTERN = re.compile(r"^- callback_url:\s*(.+)$", re.MULTILINE)
CORRELATION_ID_PATTERN = re.compile(r"^- correlation_id:\s*(.+)$", re.MULTILINE)
MESSAGE_VALUE_PATTERN = re.compile(r'"msg":\s*"((?:[^"\\]|\\.)*)"')
FENCED_YAML_PATTERN = re.compile(r"```(?:yaml)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return float(value)


def _first_non_empty(*values: str | None) -> str | None:
    for value in values:
        if value and value.strip():
            return value.strip()
    return None


def _normalize_aap_url(value: str) -> str:
    base_url = value.rstrip("/")
    if "/api/" in base_url:
        return base_url
    return f"{base_url}/api/v2"


@dataclass(frozen=True)
class BridgeSettings:
    aap_url: str
    aap_token: str | None
    aap_username: str | None
    aap_password: str | None
    aap_verify_ssl: bool
    kafka_bootstrap_servers: list[str]
    kafka_topic: str
    kafka_group_id: str
    kafka_auto_offset_reset: str
    control_plane_api_key: str
    control_plane_verify_ssl: bool
    lightspeed_template_name: str
    lightspeed_template_id: int | None
    lightspeed_prompt_var_name: str
    provider_name: str
    request_timeout_seconds: float
    poll_seconds: float
    retry_sleep_seconds: float


@dataclass(frozen=True)
class GenerationInstruction:
    raw_text: str
    prompt_text: str
    callback_url: str
    correlation_id: str
    incident_id: str | None
    summary_line: str


class PlaybookGenerationError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        job_id: int | None = None,
        template_id: int | None = None,
    ) -> None:
        super().__init__(message)
        self.job_id = job_id
        self.template_id = template_id


def load_settings() -> BridgeSettings:
    aap_url = _first_non_empty(os.getenv("AAP_URL"), os.getenv("AAP_CONTROLLER_URL"))
    if not aap_url:
        raise ValueError("AAP_URL or AAP_CONTROLLER_URL is required")
    aap_token = _first_non_empty(os.getenv("AAP_TOKEN"))
    aap_username = _first_non_empty(os.getenv("AAP_USERNAME"), os.getenv("AAP_CONTROLLER_USERNAME"))
    aap_password = _first_non_empty(os.getenv("AAP_PASSWORD"), os.getenv("AAP_CONTROLLER_PASSWORD"))
    if not aap_token and not (aap_username and aap_password):
        raise ValueError("Set AAP_TOKEN or both AAP_USERNAME/AAP_PASSWORD")

    bootstrap_servers = [
        server.strip()
        for server in str(os.getenv("KAFKA_BOOTSTRAP_SERVERS") or "").split(",")
        if server.strip()
    ]
    if not bootstrap_servers:
        raise ValueError("KAFKA_BOOTSTRAP_SERVERS is required")

    control_plane_api_key = _first_non_empty(os.getenv("CONTROL_PLANE_API_KEY"))
    if not control_plane_api_key:
        raise ValueError("CONTROL_PLANE_API_KEY is required")

    template_id_value = _first_non_empty(os.getenv("LIGHTSPEED_TEMPLATE_ID"))
    lightspeed_template_id = int(template_id_value) if template_id_value else None

    return BridgeSettings(
        aap_url=_normalize_aap_url(aap_url),
        aap_token=aap_token,
        aap_username=aap_username,
        aap_password=aap_password,
        aap_verify_ssl=_env_flag("AAP_VERIFY_SSL", _env_flag("AAP_CONTROLLER_VERIFY_SSL", False)),
        kafka_bootstrap_servers=bootstrap_servers,
        kafka_topic=os.getenv("PLAYBOOK_GENERATION_KAFKA_TOPIC", "aiops-ansible-playbook-generate-instruction"),
        kafka_group_id=os.getenv("PLAYBOOK_GENERATION_CONSUMER_GROUP_ID", "aap-playbook-bridge"),
        kafka_auto_offset_reset=os.getenv("PLAYBOOK_GENERATION_AUTO_OFFSET_RESET", "latest"),
        control_plane_api_key=control_plane_api_key,
        control_plane_verify_ssl=_env_flag("CONTROL_PLANE_VERIFY_SSL", False),
        lightspeed_template_name=os.getenv(
            "LIGHTSPEED_TEMPLATE_NAME",
            "Lightspeed Remediation Playbook Generator",
        ),
        lightspeed_template_id=lightspeed_template_id,
        lightspeed_prompt_var_name=os.getenv("LIGHTSPEED_PROMPT_VAR_NAME", "lightspeed_prompt"),
        provider_name=os.getenv("PLAYBOOK_GENERATION_PROVIDER_NAME", "aap-lightspeed"),
        request_timeout_seconds=_env_float("PLAYBOOK_GENERATION_REQUEST_TIMEOUT_SECONDS", 60.0),
        poll_seconds=_env_float("PLAYBOOK_GENERATION_POLL_SECONDS", 2.0),
        retry_sleep_seconds=_env_float("PLAYBOOK_GENERATION_RETRY_SLEEP_SECONDS", 5.0),
    )


def parse_instruction(instruction_text: str) -> GenerationInstruction:
    raw_text = str(instruction_text or "").strip()
    if not raw_text:
        raise ValueError("Instruction payload is empty")

    callback_match = CALLBACK_URL_PATTERN.search(raw_text)
    if not callback_match:
        raise ValueError("Instruction is missing callback_url")
    correlation_match = CORRELATION_ID_PATTERN.search(raw_text)
    if not correlation_match:
        raise ValueError("Instruction is missing correlation_id")

    callback_url = callback_match.group(1).strip()
    correlation_id = correlation_match.group(1).strip()

    callback_contract_index = raw_text.find("Callback contract:")
    prompt_text = raw_text[:callback_contract_index] if callback_contract_index >= 0 else raw_text
    prompt_text = re.sub(r"(?m)^- callback_url:.*$", "", prompt_text)
    prompt_text = re.sub(r"(?m)^- correlation_id:.*$", "", prompt_text)
    prompt_text = re.sub(r"\n{3,}", "\n\n", prompt_text).strip()

    summary_line = raw_text.splitlines()[0].strip()
    incident_id_match = INCIDENT_ID_PATTERN.search(callback_url)
    incident_id = incident_id_match.group(1) if incident_id_match else None

    return GenerationInstruction(
        raw_text=raw_text,
        prompt_text=prompt_text,
        callback_url=callback_url,
        correlation_id=correlation_id,
        incident_id=incident_id,
        summary_line=summary_line,
    )


def _valid_playbook_yaml(candidate: str) -> bool:
    try:
        payload = yaml.safe_load(candidate)
    except yaml.YAMLError:
        return False
    if isinstance(payload, list) and payload:
        return all(isinstance(item, dict) for item in payload)
    if isinstance(payload, dict):
        return "hosts" in payload and "tasks" in payload
    return False


def extract_playbook_yaml(stdout_text: str) -> str:
    stdout_text = str(stdout_text or "")

    for escaped_message in reversed(MESSAGE_VALUE_PATTERN.findall(stdout_text)):
        try:
            candidate = json.loads(f"\"{escaped_message}\"").strip()
        except json.JSONDecodeError:
            continue
        if _valid_playbook_yaml(candidate):
            return candidate.rstrip() + "\n"

    for match in FENCED_YAML_PATTERN.findall(stdout_text):
        candidate = match.strip()
        if _valid_playbook_yaml(candidate):
            return candidate.rstrip() + "\n"

    raise ValueError("Could not extract a valid Ansible playbook from job stdout")


class AAPClient:
    def __init__(self, settings: BridgeSettings) -> None:
        self.settings = settings
        auth = None
        if not settings.aap_token and settings.aap_username and settings.aap_password:
            auth = (settings.aap_username, settings.aap_password)
        self.client = httpx.Client(
            auth=auth,
            verify=settings.aap_verify_ssl,
            timeout=settings.request_timeout_seconds,
        )

    def close(self) -> None:
        self.client.close()

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.settings.aap_token:
            headers["Authorization"] = f"Bearer {self.settings.aap_token}"
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        url = path if path.startswith("http") else f"{self.settings.aap_url}/{path.lstrip('/')}"
        response = self.client.request(
            method,
            url,
            headers=self._headers(),
            params=params,
            json=json_body,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"AAP API {response.status_code} for {url}: {response.text}")
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return response.json()
        return response.text

    def resolve_template_id(self) -> int:
        if self.settings.lightspeed_template_id is not None:
            return self.settings.lightspeed_template_id
        template_data = self.request(
            "GET",
            "job_templates/",
            params={"name": self.settings.lightspeed_template_name},
        )
        results = template_data.get("results") if isinstance(template_data, dict) else None
        if not results:
            raise PlaybookGenerationError(
                f"Could not find AAP job template '{self.settings.lightspeed_template_name}'",
            )
        template_id = results[0].get("id")
        if not template_id:
            raise PlaybookGenerationError(
                f"AAP job template '{self.settings.lightspeed_template_name}' is missing an id",
            )
        return int(template_id)

    def wait_for_job(self, job_id: int) -> dict[str, Any]:
        while True:
            job_status = self.request("GET", f"jobs/{job_id}/")
            status = str(job_status.get("status") or "")
            if status in TERMINAL_JOB_STATES:
                return job_status
            time.sleep(self.settings.poll_seconds)

    def generate_playbook(self, instruction: GenerationInstruction) -> dict[str, Any]:
        template_id = self.resolve_template_id()
        launch_response = self.request(
            "POST",
            f"job_templates/{template_id}/launch/",
            json_body={"extra_vars": {self.settings.lightspeed_prompt_var_name: instruction.prompt_text}},
        )
        job_id = launch_response.get("id") if isinstance(launch_response, dict) else None
        if not job_id:
            raise PlaybookGenerationError(
                f"Could not launch Lightspeed job: {launch_response}",
                template_id=template_id,
            )

        job_status = self.wait_for_job(int(job_id))
        terminal_status = str(job_status.get("status") or "")
        stdout_text = str(self.request("GET", f"jobs/{job_id}/stdout/", params={"format": "txt"}))

        if terminal_status != "successful":
            raise PlaybookGenerationError(
                f"Lightspeed job {job_id} finished with status '{terminal_status}'",
                job_id=int(job_id),
                template_id=template_id,
            )

        try:
            playbook_yaml = extract_playbook_yaml(stdout_text)
        except ValueError as exc:
            raise PlaybookGenerationError(
                str(exc),
                job_id=int(job_id),
                template_id=template_id,
            ) from exc

        return {
            "template_id": template_id,
            "job_id": int(job_id),
            "playbook_yaml": playbook_yaml,
        }


def build_success_payload(
    settings: BridgeSettings,
    instruction: GenerationInstruction,
    generation_result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "correlation_id": instruction.correlation_id,
        "status": "generated",
        "title": f"AI-generated Ansible playbook for incident {instruction.incident_id or 'workflow'}",
        "description": instruction.summary_line,
        "summary": "AAP Lightspeed generated a reviewable playbook from the Kafka instruction.",
        "playbook_yaml": generation_result["playbook_yaml"],
        "provider_name": settings.provider_name,
        "provider_run_id": str(generation_result["job_id"]),
        "metadata": {
            "source": "kafka",
            "kafka_topic": settings.kafka_topic,
            "template_id": generation_result["template_id"],
            "template_name": settings.lightspeed_template_name,
            "job_id": generation_result["job_id"],
        },
    }


def build_failure_payload(
    settings: BridgeSettings,
    instruction: GenerationInstruction,
    error_message: str,
    *,
    job_id: int | None = None,
    template_id: int | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "source": "kafka",
        "kafka_topic": settings.kafka_topic,
        "template_name": settings.lightspeed_template_name,
    }
    if template_id is not None:
        metadata["template_id"] = template_id
    if job_id is not None:
        metadata["job_id"] = job_id

    return {
        "correlation_id": instruction.correlation_id,
        "status": "failed",
        "error": error_message,
        "provider_name": settings.provider_name,
        "provider_run_id": str(job_id) if job_id is not None else None,
        "metadata": metadata,
    }


def post_callback(settings: BridgeSettings, instruction: GenerationInstruction, payload: dict[str, Any]) -> None:
    headers = {
        "Content-Type": "application/json",
        "x-api-key": settings.control_plane_api_key,
    }
    response = httpx.post(
        instruction.callback_url,
        headers=headers,
        json=payload,
        timeout=settings.request_timeout_seconds,
        verify=settings.control_plane_verify_ssl,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Control-plane callback {response.status_code} for {instruction.callback_url}: {response.text}"
        )


def process_message(settings: BridgeSettings, client: AAPClient, raw_message: str) -> None:
    instruction = parse_instruction(raw_message)
    try:
        generation_result = client.generate_playbook(instruction)
        payload = build_success_payload(settings, instruction, generation_result)
    except PlaybookGenerationError as exc:
        payload = build_failure_payload(
            settings,
            instruction,
            str(exc),
            job_id=exc.job_id,
            template_id=exc.template_id,
        )
    post_callback(settings, instruction, payload)


def run_consumer() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if KafkaConsumer is None:
        raise RuntimeError("kafka-python is not installed")
    settings = load_settings()
    LOGGER.info(
        "Starting playbook bridge topic=%s group=%s bootstrap=%s",
        settings.kafka_topic,
        settings.kafka_group_id,
        ",".join(settings.kafka_bootstrap_servers),
    )
    consumer = KafkaConsumer(
        settings.kafka_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_group_id,
        auto_offset_reset=settings.kafka_auto_offset_reset,
        enable_auto_commit=False,
        value_deserializer=lambda value: value.decode("utf-8"),
    )
    client = AAPClient(settings)
    try:
        for message in consumer:
            LOGGER.info(
                "Processing instruction topic=%s partition=%s offset=%s",
                message.topic,
                message.partition,
                message.offset,
            )
            try:
                process_message(settings, client, str(message.value))
            except Exception:
                LOGGER.exception("Failed to process Kafka instruction at offset %s", message.offset)
                time.sleep(settings.retry_sleep_seconds)
                continue
            consumer.commit()
    finally:
        client.close()
        consumer.close()


def main() -> None:
    run_consumer()


if __name__ == "__main__":
    main()
